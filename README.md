# Security Analysis Server

[![Actions Status](https://github.com/gridsuite/security-analysis-server/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/gridsuite/security-analysis-server/actions)
[![Coverage Status](https://sonarcloud.io/api/project_badges/measure?project=org.gridsuite%3Asecurity-analysis-server&metric=coverage)](https://sonarcloud.io/component_measures?id=org.gridsuite%3Asecurity-analysis-server&metric=coverage)
[![MPL-2.0 License](https://img.shields.io/badge/license-MPL_2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)

## Description

The **security-analysis-server** is a microservice of the [GridSuite](https://github.com/gridsuite) platform dedicated to **power network security analysis computation**.

Security analysis evaluates the impact of a set of contingencies (network element outages) on a power system. It simulates each contingency and detects any resulting **limit violations** (current, voltage, active power), assessing whether the network can safely withstand those events.

It provides the following capabilities:

- **Run security analysis computations** on a network using configurable providers (OpenLoadFlow, DynaFlow).
- **N result**: detect and store limit violations on the base case (no contingency applied), with filtering, sorting and CSV export.
- **N-k contingencies result**: for each contingency, report the computation status and the list of limit violations triggered, with filtering, pagination, sorting and CSV export.
- **N-k constraints result**: group results by constrained equipment (subject), listing all contingencies that cause a violation on it, with filtering, pagination, sorting and CSV export.
- **N-k cut-off power result**: report connectivity impacts — buses and loads disconnected as a consequence of each contingency — with filtering, pagination and CSV export.
- **Manage parameter sets** (create, read, update, duplicate, delete) with provider-aware limit reduction configurations per voltage level and limit duration.
- Run computations either **synchronously** (direct response) or **asynchronously** (via a RabbitMQ message queue).

---

## Technical Stack

- Spring Boot (Web, Data JPA, Actuator, Cloud Stream)
- PostgreSQL
- Liquibase
- RabbitMQ via Spring Cloud Stream
- API documentation: OpenAPI / Swagger (`springdoc`)
- Micrometer / Prometheus
- [gridsuite-computation](https://github.com/gridsuite/computation)

---

## Development Scripts

Build Docker image

```shell
mvn install -DskipTests -Dpowsybl.docker.install
```

Please read [liquibase usage](https://github.com/powsybl/powsybl-parent/#liquibase-usage) for instructions to automatically generate changesets. After you generated a changeset do not forget to add it to git and in `src/main/resources/db/changelog/db.changelog-master.yml`.

---

## Interactions with Other Microservices

```text
┌───────────────────────────────┐
│  security-analysis-server     │──► network-store-server  (read network topology)
│                               │──► filter-server          (resolve equipment filters for limit violations)
│                               │──► actions-server         (resolve contingency lists)
│                               │──► loadflow-server        (fetch load flow parameters)
│                               │──► report-server          (post computation functional logs)
└───────────────────────────────┘
          ▲  ▼
       RabbitMQ (sa.run / sa.cancel / sa.result / sa.stopped / sa.cancelfailed)
```

---

## Asynchronous Execution Flow

1. The controller publishes a message on the `sa.run` queue.
2. Parallel consumers (`consumeRun1`, `consumeRun2`) process messages concurrently for load balancing.
3. The computation result is published on `sa.result`.
4. Cancellation of a running computation goes through the `sa.cancel` queue.
5. Dead-letter queues (`sa.run.dlx`) and quorum queues ensure reliability.

---

## Result Data

A security analysis result is composed of several complementary datasets exposed through the REST API:

| Dataset | Description |
|---|---|
| **N result** | Limit violations on the base case (pre-contingency state): subject equipment, violation type, value, limit, side. Supports column filters, global filters (network-element-based), sorting and CSV export. |
| **N-k contingencies result** | Per-contingency results: computation status, list of limit violations triggered. Supports column filters, global filters, pagination, sorting and CSV export. |
| **N-k constraints result** | Results grouped by constrained equipment: for each subject, the list of contingencies causing a violation. Supports column filters, global filters, pagination, sorting and CSV export. |
| **N-k cut-off power result** | Connectivity impacts: buses and loads disconnected following each contingency. Supports column filters, global filters, pagination and CSV export. |

---

## Parameters and Limit Reductions

Security analysis parameters include:

- **Provider** selection (OpenLoadFlow, DynaFlow).
- **Contingency lists**: one or more lists of contingencies to simulate, resolved at runtime via the actions-server.
- **Limit reductions**: a matrix of reduction factors applied to thermal limits before violation detection, configurable per voltage level (nominal voltage range) and per limit duration (TATL duration ranges). Default values are defined in `application.yaml`.

---

## Built on gridsuite-computation

The following capabilities are provided by the gridsuite-computation shared library:

- asynchronous run/cancel pipeline,
- transactional result notifications,
- network equipment filtering,
- report integration,
- Micrometer observability.

The security-analysis-server itself focuses on security-analysis-specific logic (parameters, contingency resolution, result model, providers) and delegates the common computation infrastructure to this lib.

---

## Useful Links

You can find [information on OpenLoadFlow here](https://powsybl.readthedocs.io/projects/powsybl-open-loadflow/en/latest/) and [on DynaFlow here](https://dynawo.github.io/about/dynaflow.html)```
