from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uuid

app = FastAPI()

# In-memory storage for notebooks and their associated clients
notebooks = {}
clients = {}  # Map notebook_id to a list of connected clients

# HTML for testing the editor (minimal frontend for now)
html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Collaborative Code Editor</title>
    </head>
    <body>
        <h1>Collaborative Code Editor</h1>
        <label for="notebookId">Enter Notebook ID:</label>
        <input type="text" id="notebookId" placeholder="Enter existing notebook ID" style="width: 80%;"><br>
        <button onclick="connectToNotebook()">Join or Create Notebook</button><br><br>
        
        <div id="notebookIdDisplay"></div> <!-- New div to display notebook ID -->
        
        <textarea id="code" style="width:80%;height:300px;" placeholder="Start typing..."></textarea>

        <script>
            function connectToNotebook() {
                const notebookId = document.getElementById("notebookId").value.trim();

                // If notebookId is provided, try to join the notebook; otherwise, create a new one
                const url = notebookId ? `/join/${notebookId}` : "/new";

                fetch(url)
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            alert(data.error);
                            return;
                        }

                        // Show the notebook ID if a new notebook is created
                        if (!notebookId) {
                            document.getElementById("notebookIdDisplay").innerText = `Your new notebook ID is: ${data.notebook_id}`;
                        }

                        const ws = new WebSocket(data.url);
                        const codeArea = document.getElementById("code");

                        ws.onopen = () => {
                            alert("Connected to the notebook!");
                        };

                        ws.onmessage = (event) => {
                            codeArea.value = event.data;
                        };

                        codeArea.addEventListener("input", () => {
                            ws.send(codeArea.value);
                        });

                        ws.onclose = () => {
                            alert("Disconnected from the notebook.");
                        };
                    });
            }
        </script>
    </body>
</html>


"""

@app.get("/")
async def get():
    return HTMLResponse(html)

@app.get("/new")
def create_notebook():
    notebook_id = str(uuid.uuid4())
    notebooks[notebook_id] = ""  # Initialize notebook content
    clients[notebook_id] = []  # Initialize client list
    return {"notebook_id": notebook_id, "url": f"ws://localhost:8000/ws/{notebook_id}"}

@app.get("/join/{notebook_id}")
def join_notebook(notebook_id: str):
    if notebook_id not in notebooks:
        return {"error": "Notebook not found"}
    return {"notebook_id": notebook_id, "url": f"ws://localhost:8000/ws/{notebook_id}"}

@app.websocket("/ws/{notebook_id}")
async def websocket_endpoint(websocket: WebSocket, notebook_id: str):
    if notebook_id not in notebooks:
        await websocket.close()
        return

    await websocket.accept()
    clients[notebook_id].append(websocket)  # Add the client to the notebook's list
    print(f"Client connected to notebook {notebook_id}. Total clients: {len(clients[notebook_id])}")
    
    try:
        # Send current notebook content to the newly connected client
        await websocket.send_text(notebooks[notebook_id])

        while True:
            data = await websocket.receive_text()
            print(f"Received data from client: {data}")

            # Update the notebook content
            notebooks[notebook_id] = data

            # Broadcast the updated content to all clients except the sender
            for client in clients[notebook_id]:
                if client != websocket:
                    await client.send_text(data)

    except WebSocketDisconnect:
        print(f"Client disconnected from notebook {notebook_id}")
        clients[notebook_id].remove(websocket)  # Remove client on disconnect

        # Clean up if no clients are connected to the notebook
        if not clients[notebook_id]:
            del clients[notebook_id]
            del notebooks[notebook_id]
            print(f"Notebook {notebook_id} closed (no active clients).")
