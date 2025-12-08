from flask import Flask, request, jsonify
import threading
import time
from brain import Brain
from knowledge_base import init_db, create_mission, update_mission, get_mission, add_finding
from tools.registry import get_tool_instance

app = Flask(__name__)
brain = Brain()

# Initialize DB
init_db()

def execute_mission_loop(mission_id, initial_target, goal):
    """
    The main autonomous loop: Think -> Act -> Observe -> Reflect.
    """
    mission_context = {
        "target": initial_target,
        "history": []
    }

    status = "STARTED"
    update_mission(mission_id, status=status)

    max_steps = 10 # Safety break
    steps = 0

    while status != "COMPLETE" and steps < max_steps:
        steps += 1
        print(f"--- Step {steps} ---")

        # 1. THINK
        decision = brain.think(mission_context, goal)
        thought = decision.get("thought", "No thought provided.")
        plan = decision.get("plan", [])
        status = decision.get("status", "CONTINUE")

        print(f"Brain Thought: {thought}")
        update_mission(mission_id, plan=plan, context=mission_context)

        if status == "COMPLETE":
            print("Mission accomplished.")
            break

        # 2. ACT
        for step in plan:
            tool_name = step.get("tool")
            params = step.get("params", {})

            # Ensure target is passed if missing (generic fallback)
            if "target" not in params and "url" not in params:
                params["target"] = initial_target

            tool = get_tool_instance(tool_name)
            if tool:
                print(f"Executing {tool_name}...")

                # 3. OBSERVE
                result = tool.run(params)

                # Update context history
                mission_context["history"].append({
                    "tool": tool_name,
                    "params": params,
                    "result": result
                })

                # Log raw finding
                add_finding(initial_target, tool_name, "Tool Output", result)

                # 4. REFLECT
                print("Reflecting on result...")
                brain.reflect(initial_target, tool_name, result)

            else:
                print(f"Tool {tool_name} not found.")

        # Sleep briefly to be nice to CPUs/APIs
        time.sleep(1)

    update_mission(mission_id, status="COMPLETED")

@app.route('/mission', methods=['POST'])
def start_mission():
    data = request.json
    target = data.get("target")
    goal = data.get("goal", "Find vulnerabilities")

    if not target:
        return jsonify({"error": "Target is required"}), 400

    mission_id = create_mission(target, goal)

    # Start execution in background
    thread = threading.Thread(target=execute_mission_loop, args=(mission_id, target, goal))
    thread.start()

    return jsonify({
        "mission_id": mission_id,
        "status": "STARTED",
        "message": "Autonomous agent loop initiated."
    })

@app.route('/mission/<int:mission_id>', methods=['GET'])
def get_mission_status(mission_id):
    mission = get_mission(mission_id)
    if mission:
        return jsonify(dict(mission))
    return jsonify({"error": "Mission not found"}), 404

if __name__ == '__main__':
    # Running securely on localhost. Set debug=False for production.
    app.run(debug=False, host='127.0.0.1', port=5000)
