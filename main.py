if __name__ == "__main__":
    import PySwitch.startup as startup
    startup.ensure_singleton()
    startup.setup_logging()

    from PySwitch.common import Env
    env = Env.Get()
    startup.add_file_handler(env.config_directory / "pyswitch.log")

    # prepare core before application start to avoid surpises
    import PySwitch.network as network
    core = network.Core.Get()

    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        from PySwitch.gui import Application
    
    exit_code = Application.Run()
    core.Shutdown()
    import sys
    sys.exit(exit_code)

# import subprocess, sys

# def _run_elevated(ps_script: str) -> None:
#     subprocess.run([
#         "powershell", "-Command",
#         f"Start-Process powershell -Verb RunAs -ArgumentList '-Command \"{ps_script}\"' -Wait"
#     ], check=True)

# def unbind_stack(nic_name: str) -> None:
#     _run_elevated(
#         f"Disable-NetAdapterBinding -Name '{nic_name}' -ComponentID ms_tcpip;"
#         f"Disable-NetAdapterBinding -Name '{nic_name}' -ComponentID ms_tcpip6"
#     )

# Where is enable?
