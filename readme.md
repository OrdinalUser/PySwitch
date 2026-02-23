# Dev notes

## References

- [assignment file](./docs/assignment.pdf)

## "Compilation" & running

- ensure a proper Python environment
  - [uv](https://docs.astral.sh/uv/) (highly recommended) or use [pip venv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)
  - install [requirements](./requirements.txt)
- run the [main.py](./main.py) file via Python

## Required libraries and their usage

### GUI

- PySide6 (Qt Python Wrapper)
- PySide6-Fluent-Widgets (Qt Fluent Widgets for cohesive styling)

### Network

- scapy (network card interaction and Windows interface fetching)
- wpcap.dll (system dll, used for inbound/outbound frames)

### Config

- dotenv (reading .env files)
- tomli_w (writing .toml files)
- pydantic (type checking and serialization)

### Other

- watchdog (file watching)
- psutil (querying Windows state)
