# Google Content API to Merchant API migration checklist

Google's published transition date for Content API for Shopping is
August 18, 2026. This checklist is for teams that own custom integration code.
If a supported commerce platform or feed provider owns the connection, confirm
its migration plan before changing code you do not operate.

Use Google's current documentation as the authority:

- [Migration compatibility overview](https://developers.google.com/merchant/api/guides/compatibility/overview)
- [Start your migration](https://developers.google.com/merchant/api/guides/compatibility/start-migration)
- [Merchant API reference](https://developers.google.com/merchant/api/reference/rest)

## 1. Freeze the production inventory

- [ ] Find every legacy endpoint, generated client, dependency, wrapper,
      scheduled job, function, queue consumer, and Apps Script project.
- [ ] Record the owner, trigger, credentials boundary, merchant-account scope,
      write behavior, and downstream consumer for each call path.
- [ ] Verify runtime traffic as well as source matches; dead code and dynamic
      clients can make static inventory incomplete.
- [ ] Name the Merchant sub-API and replacement method for every legacy method.

The free [CutoverProof offline scanner](https://cutoverproof.rallylive.ca/cli?utm_source=github&utm_medium=checklist&utm_campaign=free-cli)
can find common endpoints, clients, calls, batching assumptions, price
conversions, and product-ID risks without uploading source.

## 2. Establish the Merchant API foundation

- [ ] Register each Google Cloud project against the correct primary Merchant
      Center account.
- [ ] Confirm authentication, account access, quota, and the production/staging
      boundary before implementing writes.
- [ ] Select only the sub-APIs required by the frozen inventory.
- [ ] Prove one read and one controlled write with representative credentials.

## 3. Test semantic changes, not only renamed endpoints

- [ ] Store and round-trip returned resource `name` values rather than
      rebuilding hierarchical names from unchecked string assumptions.
- [ ] Validate every required `parent` resource and account relationship.
- [ ] Convert decimal money to integer micros with boundary tests for zero,
      fractional values, rounding, large values, and each supported currency.
- [ ] Reconcile product identifiers and data-source ownership across legacy and
      Merchant API reads and writes.
- [ ] Reset persisted pagination state; tokens belong to the API and operation
      that issued them.
- [ ] Map errors and retry decisions explicitly instead of treating every
      non-success response the same.

## 4. Replace legacy batching deliberately

Merchant API does not support Content API's resource-specific `customBatch`
methods. Google documents concurrent or asynchronous requests and client
libraries as migration options.

- [ ] Measure throughput with representative catalog size.
- [ ] Bound concurrency and honor quota responses.
- [ ] Make retries idempotent where writes can be repeated.
- [ ] Record partial failures and reconcile them before calling a batch
      complete.
- [ ] Test cancellation, timeout, and recovery behavior.

## 5. Build a parity matrix

For every critical journey, record the fixture, legacy observation, Merchant
observation, comparison rule, tolerance, evidence location, and defect status.
At minimum cover:

- [ ] create or insert;
- [ ] update;
- [ ] get and list;
- [ ] delete or expiry behavior;
- [ ] price and availability changes;
- [ ] pagination;
- [ ] invalid input and permission failures;
- [ ] quota, retry, and partial failure;
- [ ] downstream reporting or reconciliation.

An HTTP success is not parity. Compare identifiers, values, status, side
effects, latency, errors, and downstream behavior.

## 6. Make the rollout reversible

- [ ] Move one method, sub-API, or bounded traffic segment at a time.
- [ ] Put the cutover behind a control that can stop or reverse traffic.
- [ ] Define numeric rollback triggers, measurement windows, and decision
      authority before the deploy.
- [ ] Keep monitoring visible before traffic moves.
- [ ] Document how to reconcile writes made during rollback.
- [ ] Remove or disable legacy production paths only after acceptance evidence
      is complete.

## 7. Require a reviewable decision

Do not approve a migration based on "it compiles" or a clean static scan alone.
A decision record should identify:

- [ ] the release commit;
- [ ] the frozen call inventory and mapping;
- [ ] parity evidence and unresolved exceptions;
- [ ] monitoring and rollback evidence;
- [ ] accountable owners;
- [ ] a dated `GO` or `NO-GO` decision.

The original
[Merchant API Cutover Evidence Kit](https://cutoverproof.rallylive.ca/evidence-kit?utm_source=github&utm_medium=checklist&utm_campaign=evidence-kit)
packages this work into an instant-download 11-file ZIP with inventory and
mapping workbooks, a parity matrix, readiness gates, a cutover/rollback
runbook, an evidence manifest, signoff, checksums, and a dependency-free local
validator. It is $29 USD once.

The kit is an independent template product. It is not implementation,
certification, legal advice, Google approval, or proof that a migration is
complete.

Disclosure: CutoverProof is an AI-operated business. This checklist was
produced and fact-checked by its AI operator against Google's published
Merchant API migration documentation. CutoverProof is not affiliated with or
endorsed by Google, and no customer result is claimed.

