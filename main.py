if __name__ == "__main__":
    import PySwitch.startup as startup

    startup.ensure_singleton()
    startup.setup_logging()

    from PySwitch.common import Env

    env = Env.Get()
    startup.add_file_handler(env.config_directory / "pyswitch.log")

    # prepare core before application start to avoid surpises
    import PySwitch.network as network

    syslog_service = network.service.Service.Get(network.service.Syslog)
    startup.add_callback_handler(syslog_service.logging_callback)
    core = network.Core.Get()

    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()):
        from PySwitch.gui import Application

    exit_code = Application.Run()
    core.Shutdown()
    import sys

    sys.exit(exit_code)
