# Workflow
| ID | deadbeef |
| Name | test-workflow |
| Team | test-team |
| Project | test-project |
| Workflow Run |  |
| ID | beefdead |
| Started At | 22 Nov 21 00:00 UTC |
| Finished At | 22 Nov 21 00:10 UTC |
| State | success |
| Runner Link | chainloop.dev/runner |
# Materials
| Name | Type | Value |
| --- | --- | --- |
| image | CONTAINER_IMAGE | index.docker.io/bitnami/nginx@sha256:264f55a6ff9cec2f4742a9faacc033b29f65c04dd4480e71e23579d484288d61 |
| skynet-sbom | SBOM_CYCLONEDX_JSON | sbom.cyclonedx.json@sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c |
| skynet2-sbom | SBOM_CYCLONEDX_JSON | sbom.cyclonedx.json@sha256:16159bb881eb4ab7eb5d8afc5350b0feeed1e31c0a268e355e74f9ccbe885e0c |
# Environment Variables
| Name | Value |
| --- | --- |
| owner | john-c@chainloop.dev |
| project | chatgpt |

Get Full Attestation

$ chainloop workflow run describe --id beefdead -o statement