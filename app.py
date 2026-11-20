from Nexa import NXserver

from novanx.config import Settings
from novanx.routes import register_routes

settings = Settings.from_env()
app = NXserver(
    "NovaNX",
    port=settings.port,
    host=settings.host,
    static_folder="static",
    template_folder="templates",
    max_body_size=26 * 1024 * 1024,
    debug=True
)
register_routes(app)


if __name__ == "__main__":
    app.run()
