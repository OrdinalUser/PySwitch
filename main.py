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
    Application.Run()
