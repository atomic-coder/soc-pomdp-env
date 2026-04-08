import uvicorn
from models import SocAction, SocObservation
from .SOC_POMDP_environment import SocEnvironment

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required for the web interface. Install dependencies with '\n    uv sync\n'"
    ) from e

# Create the app
app = create_app(
    SocEnvironment,
    SocAction,
    SocObservation,
    env_name="SOC_POMDP",
    max_concurrent_envs=1,
)

def main(host: str = "0.0.0.0", port: int = 8000):
    """
    Standard entry point for the OpenEnv validator.
    The validator expects this function to be callable with host/port.
    """
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    # Ensure BOTH host and port are handled
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    
    main(host=args.host, port=args.port)                