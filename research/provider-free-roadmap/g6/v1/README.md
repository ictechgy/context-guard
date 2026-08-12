# G6 immutable prepared-unapproved packet

G6 is preparation only. `preparation-packet.json` has the immutable status
`prepared_unapproved`, grants no authority, contains no approval evidence, and
cannot be converted into an executable command. Repository artifacts cannot
change that state: there is no approval branch, runner, execution entry point,
provider or model choice, credential reference, network destination, output
root, retention choice, spend limit, or external decision.

Every execution selection is `blocking_unselected` with a null value. Expiry,
revocation, and one-use requirements are also externally blocking and null.
The only copied experimental facts are the frozen G5 capacity constraints of
240 scheduled units and zero replacement blocks; they have authority effect
`none`. Publication, runtime activation, npm activity, and claims remain
separate, disabled surfaces.

Any future external approval system would have to provide exact provider and
observer identities; operation surface, version, and receipt schema; a bounded
credential consumer and scope allowlist without secret values; an exact
scheme/host/port destination allowlist with redirects and proxies denied; and
an exact runtime binary, version, hash, argv, and environment without a shell.
It must also bind the source candidate and output root/mode, finite retention,
at most 240 calls, finite spend and currency, timeout, expiry, revocation
handle, and one-use nonce. Scope expansion is forbidden and claims require a
later evidence review. These are boolean requirements only: no materializing
value is stored here and they grant no authority.

The captured-byte verifier checks the exact G5 lock, tree, preregistration,
schedule, three-schema set, and verifier identities. Its success means only
that captured bytes match this prepared-unapproved contract. It explicitly
returns authorization false, and direct mutable execution always refuses.

Run the provider-free integrity profile only:

```sh
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py run --contract research/provider-free-roadmap/boundary-contract.json --profile g6-prepared-unapproved
```

This command does not access a provider, network, credential, runtime surface,
or npm; it does not publish, activate, execute an experiment, or make a token,
USD, performance, readiness, generalization, or savings claim.
