import argparse
import base64
import json
import runpy
import sys
import traceback


def _write(message):
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _load_user_namespace(config):
    script_kind = config.get("scriptKind", "inline")
    if script_kind == "file":
        script_path = config.get("scriptPath")
        if not script_path:
            raise RuntimeError("scriptPath is empty")
        return runpy.run_path(script_path)

    namespace = {
        "__name__": "__custom_protocol__",
        "__builtins__": __builtins__,
    }
    code = config.get("inlineCode") or ""
    exec(compile(code, "<custom_protocol>", "exec"), namespace)
    return namespace


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _normalize_frames(result):
    if result is None:
        return []
    if isinstance(result, dict):
        result = result.get("frames", [])
    if not isinstance(result, (list, tuple)):
        raise RuntimeError("feed(data) must return a frame list")
    if not result:
        return []
    if all(_is_number(item) for item in result):
        return [[float(item) for item in result]]

    frames = []
    for frame in result:
        if frame is None:
            continue
        if not isinstance(frame, (list, tuple)):
            raise RuntimeError("each frame must be a list of numbers")
        frames.append([float(item) for item in frame])
    return frames


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as file:
        config = json.load(file)

    namespace = _load_user_namespace(config)
    feed = namespace.get("feed")
    if not callable(feed):
        raise RuntimeError("custom protocol script must define feed(data)")
    reset = namespace.get("reset")
    if callable(reset):
        reset()

    _write({"type": "ready"})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            message_type = message.get("type")
            if message_type == "stop":
                break
            if message_type == "reset":
                if callable(reset):
                    reset()
                _write({"type": "reset"})
                continue
            if message_type != "feed":
                continue
            data = base64.b64decode(message.get("data", ""))
            frames = _normalize_frames(feed(data))
            if frames:
                _write({"type": "frames", "frames": frames})
        except Exception as error:
            _write(
                {
                    "type": "error",
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                }
            )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        _write(
            {
                "type": "fatal",
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
        )
        sys.exit(1)
