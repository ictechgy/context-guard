from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "context-guard-kit" / "task_memory.py"


class TaskMemoryTests(unittest.TestCase):
    def make_project(self, parent: Path, name: str = "project") -> Path:
        project = parent / name
        project.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=project, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=project, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=project, check=True)
        (project / "source.txt").write_text("stable source\n", encoding="utf-8")
        subprocess.run(["git", "add", "source.txt"], cwd=project, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=project, check=True)
        return project

    def run_cli(self, *args: str, cwd: Path, stdin: str = "", ok: bool = True) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(
            [sys.executable, str(CLI), *args], cwd=cwd, input=stdin,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if ok:
            self.assertEqual(proc.returncode, 0, proc.stderr)
        else:
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
        return proc

    def put(self, project: Path, content: str = "remember this exactly\n", **options: str) -> dict[str, object]:
        args = ["--root", str(project), "--store", str(project / ".memory"), "put", "--task", "task-1", "--source", "source.txt", "--json"]
        for key, value in options.items():
            args.extend(["--" + key.replace("_", "-"), value])
        return json.loads(self.run_cli(*args, cwd=project, stdin=content).stdout)

    def get(self, project: Path, handle: str, *, ok: bool = True) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "--root", str(project), "--store", str(project / ".memory"),
            "get", handle, "--task", "task-1", "--source", "source.txt", "--max-bytes", "4096",
            cwd=project, ok=ok,
        )

    def test_restart_replays_exact_content_with_opaque_handle_and_private_storage(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            project = self.make_project(Path(raw))
            receipt = self.put(project)
            handle = str(receipt["handle"])
            self.assertRegex(handle, r"^contextguard-memory:[a-f0-9]{32}$")
            self.assertNotIn(str(project), json.dumps(receipt))
            self.assertNotIn("remember this", json.dumps(receipt))
            self.assertEqual(self.get(project, handle).stdout, "remember this exactly\n")
            self.assertEqual(self.get(project, handle).stdout, "remember this exactly\n")
            missing_source = self.run_cli(
                "--root", str(project), "--store", str(project / ".memory"),
                "get", handle, "--task", "task-1", "--max-bytes", "4096",
                cwd=project, ok=False,
            )
            self.assertEqual(missing_source.stdout, "")
            self.assertEqual(stat.S_IMODE((project / ".memory").stat().st_mode), 0o700)
            for item in (project / ".memory").iterdir():
                self.assertIn(stat.S_IMODE(item.stat().st_mode), (0o600, 0o700))

    def test_source_change_revision_drift_expiry_and_tampering_fail_before_content_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            for mutation in ("source", "revision", "expiry", "content-tamper", "metadata-tamper"):
                project = self.make_project(parent, mutation)
                receipt = self.put(project, ttl_seconds="1" if mutation == "expiry" else "3600")
                handle = str(receipt["handle"])
                if mutation == "source":
                    (project / "source.txt").write_text("changed\n", encoding="utf-8")
                elif mutation == "revision":
                    (project / "other.txt").write_text("revision drift\n", encoding="utf-8")
                    subprocess.run(["git", "add", "other.txt"], cwd=project, check=True)
                    subprocess.run(["git", "commit", "-qm", "drift"], cwd=project, check=True)
                elif mutation == "expiry":
                    time.sleep(2)
                elif mutation == "content-tamper":
                    content = next((project / ".memory" / "records").glob("*.data"))
                    content.write_text("attacker content\n", encoding="utf-8")
                else:
                    metadata = next((project / ".memory" / "records").glob("*.json"))
                    document = json.loads(metadata.read_text(encoding="utf-8"))
                    document["expires_at"] = 4102444800
                    metadata.write_text(json.dumps(document), encoding="utf-8")
                proc = self.run_cli(
                    "--root", str(project), "--store", str(project / ".memory"),
                    "get", handle, "--task", "task-1", "--source", "source.txt", "--max-bytes", "4096",
                    cwd=project, ok=False,
                )
                self.assertEqual(proc.stdout, "")

    def test_secret_links_unsafe_modes_and_quota_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            secret_project = self.make_project(parent, "secret")
            secret = "ghp_" + "A" * 36
            proc = self.run_cli(
                "--root", str(secret_project), "--store", str(secret_project / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt",
                cwd=secret_project, stdin=f"token={secret}\n", ok=False,
            )
            self.assertNotIn(secret, proc.stderr)

            source_secret_project = self.make_project(parent, "source-secret")
            (source_secret_project / "source.txt").write_text(f"credential={secret}\n", encoding="utf-8")
            proc = self.run_cli(
                "--root", str(source_secret_project), "--store", str(source_secret_project / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt",
                cwd=source_secret_project, stdin="safe summary\n", ok=False,
            )
            self.assertNotIn(secret, proc.stderr)

            quota_project = self.make_project(parent, "quota")
            self.run_cli(
                "--root", str(quota_project), "--store", str(quota_project / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt", "--max-entry-bytes", "4",
                cwd=quota_project, stdin="12345", ok=False,
            )
            outside = parent / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            escape = self.run_cli(
                "--root", str(quota_project), "--store", str(quota_project / ".memory"),
                "put", "--task", "task-1", "--source", "../outside.txt",
                cwd=quota_project, stdin="safe\n", ok=False,
            )
            self.assertEqual(escape.stdout, "")
            broaden = self.run_cli(
                "--root", str(quota_project), "--store", str(quota_project / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt",
                "--max-total-bytes", "10000001", cwd=quota_project,
                stdin="safe\n", ok=False,
            )
            self.assertEqual(broaden.stdout, "")

            store_link_project = self.make_project(parent, "store-link")
            real_store = store_link_project / "real-store"
            real_store.mkdir(mode=0o700)
            (store_link_project / ".memory").symlink_to(real_store.name)
            linked_store = self.run_cli(
                "--root", str(store_link_project), "--store", str(store_link_project / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt",
                cwd=store_link_project, stdin="safe\n", ok=False,
            )
            self.assertEqual(linked_store.stdout, "")

            link_project = self.make_project(parent, "link")
            receipt = self.put(link_project)
            handle = str(receipt["handle"])
            record = next((link_project / ".memory" / "records").glob("*.data"))
            original = record.with_suffix(".saved")
            record.rename(original)
            record.symlink_to(original.name)
            self.assertEqual(self.get(link_project, handle, ok=False).stdout, "")

            hardlink_project = self.make_project(parent, "hardlink")
            receipt = self.put(hardlink_project)
            record = next((hardlink_project / ".memory" / "records").glob("*.data"))
            os.link(record, record.with_suffix(".alias"))
            self.assertEqual(self.get(hardlink_project, str(receipt["handle"]), ok=False).stdout, "")

            mode_project = self.make_project(parent, "mode")
            receipt = self.put(mode_project)
            os.chmod(mode_project / ".memory", 0o755)
            self.assertEqual(self.get(mode_project, str(receipt["handle"]), ok=False).stdout, "")

    def test_revision_identity_refuses_oversized_and_aggregate_untracked_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            oversized = self.make_project(parent, "oversized-revision")
            (oversized / "large.bin").write_bytes(b"x" * 10_000_001)
            refused = self.run_cli(
                "--root", str(oversized), "--store", str(oversized / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt",
                cwd=oversized, stdin="safe\n", ok=False,
            )
            self.assertEqual(refused.stdout, "")
            self.assertEqual(
                list((oversized / ".memory" / "records").glob("*.*")), []
            )

            aggregate = self.make_project(parent, "aggregate-revision")
            (aggregate / "first.bin").write_bytes(b"a" * 6_000_000)
            (aggregate / "second.bin").write_bytes(b"b" * 6_000_000)
            refused = self.run_cli(
                "--root", str(aggregate), "--store", str(aggregate / ".memory"),
                "put", "--task", "task-1", "--source", "source.txt",
                cwd=aggregate, stdin="safe\n", ok=False,
            )
            self.assertEqual(refused.stdout, "")
            self.assertEqual(
                list((aggregate / ".memory" / "records").glob("*.*")), []
            )

    def test_eviction_cleanup_concurrent_writers_and_cross_project_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            project = self.make_project(parent, "concurrent")
            commands = []
            for index in range(4):
                commands.append(subprocess.Popen(
                    [sys.executable, str(CLI), "--root", str(project), "--store", str(project / ".memory"),
                     "put", "--task", f"task-{index}", "--source", "source.txt", "--max-entries", "2", "--json"],
                    cwd=project, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                ))
            results = [proc.communicate(f"memory {index}\n") for index, proc in enumerate(commands)]
            self.assertTrue(all(proc.returncode == 0 for proc in commands), results)
            records = list((project / ".memory" / "records").glob("*.json"))
            self.assertLessEqual(len(records), 2)
            kept_meta = records[0]
            kept_data = kept_meta.with_suffix(".data")
            kept_data.write_text("tampered after crash\n", encoding="utf-8")
            orphan = kept_meta.parent / ("f" * 32 + ".data")
            orphan.write_text("orphaned crash write\n", encoding="utf-8")
            os.chmod(orphan, 0o600)
            cleanup = json.loads(self.run_cli(
                "--root", str(project), "--store", str(project / ".memory"), "cleanup", "--json",
                cwd=project,
            ).stdout)
            self.assertGreaterEqual(cleanup["removed"], 2)
            self.assertFalse(kept_meta.exists())
            self.assertFalse(orphan.exists())

            source = self.make_project(parent, "source-project")
            receipt = self.put(source)
            target = self.make_project(parent, "target-project")
            subprocess.run(["cp", "-R", str(source / ".memory"), str(target / ".memory")], check=True)
            proc = self.run_cli(
                "--root", str(target), "--store", str(target / ".memory"),
                "get", str(receipt["handle"]), "--task", "task-1", "--source", "source.txt", "--max-bytes", "4096",
                cwd=target, ok=False,
            )
            self.assertEqual(proc.stdout, "")


if __name__ == "__main__":
    unittest.main()
