# Legacy API security-system design notes

This document preserves the public, metadata-free content of the original
early design document. It is historical context; the V2 requirements and
domain architecture are authoritative for current implementation work.

The original DOCX contained generic design prose only. Its Word creator and
last-modifier metadata are intentionally not reproduced here.

## Idea

Use AI to assist API testing and vulnerability analysis. The system can call
controlled scripts, reuse stored data to construct requests, and classify
abnormal responses. OpenAPI or Postman descriptions are preferred because
captured traffic often does not contain every valid parameter combination.

## Preconditions

Classify APIs by behavior such as create, delete, update, query, upload,
download and authentication. Identification and execution rules should be
extensible, while uncertain classifications remain reviewable by an engineer.

Parameter analysis compares request and response names and values while
retaining each value's location in query, path, header or body. A separate
relationship layer can infer weak links between producer and consumer APIs.
Human confirmation remains part of the process, especially for dynamic or
universal parameters.

Once parameter and path relationships exist, the platform can construct
candidate requests and track whether an engineer has reviewed the resulting
combination.

## Initial implementation concept

- Parse HAR, OpenAPI and Postman inputs into normalized API records.
- Support proxy capture as an optional source, while keeping raw traffic
  private.
- Provide a Web interface for correcting endpoint actions and classifications.
- Infer parameter properties through rules and controlled validation.
- Keep authentication generic and reusable across executions.

## Historical backlog

- Associate captured values with account and role context.
- Add API version and vulnerability lifecycle management.
- Integrate scanner adapters and authorization/business-logic checks.
- Generate functional test cases from normalized endpoint knowledge.

## Early model vocabulary

- `Path`: endpoint path and behavior classification.
- `Req` / `Res`: request and response representation.
- `ReqP` / `ResP`: parameterized request and response structures.
- `ReqPV` / `ResPV`: observed parameter values.
- `Priority`: candidate-parameter priority.
- Relationship records: parameter, producer path, consumer path and observed
  value reference.
- Request composition records: path, parameter, content type and reviewer.

The early inference idea was that a shared parameter name plus overlapping
observed values across different paths indicates a candidate producer/consumer
relationship. Empty intersections or dynamic values require explicit
calibration, and mutation-capable endpoints should be manually classified
before execution.

## Mapping to the current implementation

- Endpoint behavior classification remains extensible asset metadata.
- Request/response name and value overlap produces a candidate relation only;
  archive/import never upgrades historical observations to verified facts.
- Parameter position is represented by typed locators rather than a single
  free-form position string.
- Request composition is frozen as immutable snapshots and fixture revisions.
- The original same-role assumption has become an N-principal policy matrix
  with roles, project-defined ranks, scopes, labels and attributes.
- Machine conclusions enter a review queue before a stable finding is created;
  fixes are verified by replaying the original evidence snapshot.
