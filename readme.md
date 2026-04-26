# Dev notes

## References

- [assignment file](./docs/assignment.pdf)

## "Compilation" & running

- ensure a proper Python environment
  - [uv](https://docs.astral.sh/uv/) (highly recommended)
  - install requirements from the [pyproject](./pyproject.toml) file, `uv sync`
- run the [main.py](./main.py), `uv run main.py`

## Required libraries and their usage

This list does not include libary dependencies

### GUI

- PySide6 (Qt Python Wrapper)
- PySide6-Fluent-Widgets (Qt Fluent Widgets for cohesive styling)

### Network

- scapy (network card interaction and Windows interface fetching)
- wpcap.dll (native non-python system dll, used for traffic inbound/outbound capture/transmit)
- wmi (used to register physical NIC events such as cable attach/detach)

### Config

- dotenv (reading .env files)
- tomli_w (writing .toml files)
- pydantic (type checking and serialization)

### Other

- watchdog (file watching)
- psutil and types-psutil (querying Windows state)
