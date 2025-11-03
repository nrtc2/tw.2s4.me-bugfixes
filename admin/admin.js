var logout = document.getElementById('logout')
var after = document.getElementById('after')
res = null;
data = null;
async function sendAdminRequest(actionPath, callback, opts = { get: false }) {
    try {
        const method = opts.get ? "GET" : "POST";

        const res = await fetch(`/admin/${actionPath}`, {
            method,
            credentials: "include",
            headers: !opts.get ? { "Content-Type": "application/json" } : undefined,
            body: !opts.get && opts.body ? JSON.stringify(opts.body) : undefined
        });
        if (!res.ok) {
            const errorText = await res.text();
            document.getElementById("chk").innerText = res.status + ": " + errorText;
            return; // stop here
        }
        const contentType = res.headers.get("content-type");
        let data;
        if (contentType && contentType.includes("application/json")) {
            data = await res.json();
        } else {
            data = await res.text();
        }

        callback(data);

    } catch (err) {
        document.getElementById("chk").innerText = err.message || err;
    }
}

logout.addEventListener("click", () => {
    if (confirm("Are you sure you want to log out?")) {
        sendAdminRequest('logout', (data) => {
            if (data.refresh) {
                document.body.textContent = "You may need to refresh if you want to log back."
            }
        }, { get: true })
    }
});
function normString(input) {
    if (input === undefined || input === null) return "";
    if (typeof input === "string") return input;
    if (typeof input === "function") return input.toString();
    return String(input);
}

function noop() { }


const accTableBody = document.querySelector('#accountsTable tbody');
const accSearchInput = document.getElementById('accSearchInput');
const accRefreshBtn = document.getElementById('accRefreshBtn');
const accPaginationDiv = document.getElementById('accPagination');
let accCurrentPage = 1;
let accTotalPages = 1;
const accPageSize = 10;

const connTableBody = document.querySelector('#connectionsTable tbody');
const connSearchInput = document.getElementById('connSearchInput');
const connRefreshBtn = document.getElementById('connRefreshBtn');
const connPaginationDiv = document.getElementById('connPagination');
let connCurrentPage = 1;
let connTotalPages = 1;
const connPageSize = 10;

const worldsTableBody = document.querySelector('#worldsTable tbody');
const worldSearchInput = document.getElementById('worldSearchInput');
const worldRefreshBtn = document.getElementById('worldRefreshBtn');
const worldPaginationDiv = document.getElementById('worldPagination');
let worldCurrentPage = 1;
let worldTotalPages = 1;
const worldPageSize = 10;

function formatUnixTime(unixTime) {
    if (!unixTime) return '-';
    const date = new Date(unixTime * 1000);
    const yy = String(date.getFullYear()).slice(-2);
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const dd = String(date.getDate()).padStart(2, '0');
    const hh = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    const ss = String(date.getSeconds()).padStart(2, '0');
    const weekday = date.toLocaleString('en-US', { weekday: 'short' });
    return `${yy}/${mm}/${dd} ${hh}:${min}:${ss} ${weekday}`;
}

function prettifyHeader(key) {
    const words = key.replace(/([a-z])([A-Z])/g, '$1 $2').split(/[_\s]+/);
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

function renderWorlds(data) {
    if (!data || !data.data || data.data.length === 0) {
        worldsTableBody.innerHTML = '<tr><td colspan="100%" style="text-align:center;">No worlds found.</td></tr>';
        worldPaginationDiv.innerHTML = '';
        return;
    }
    const attrKeys = Object.keys(data.data[0].attributes || {});
    const headRow = document.querySelector('#worldsTable thead tr');
    Array.from(headRow.querySelectorAll('.attrHeader')).forEach(el => el.remove());
    attrKeys.forEach(key => {
        const th = document.createElement('th');
        th.classList.add('attrHeader');
        th.innerText = prettifyHeader(key);
        th.style.width = '60px';
        headRow.insertBefore(th, headRow.querySelector('th:last-child'));
    });
    worldsTableBody.innerHTML = data.data.map(w => {
        const attrCells = attrKeys.map(k => {
            const v = w.attributes[k];
            return `<td style="text-align:center;">${v === true ? 'Yes' : v === false ? 'No' : v}</td>`;
        }).join('');
        return `<tr>
            <td>${w.id}</td>
            <td>${w.namespace}</td>
            <td>${w.name}</td>
            ${attrCells}
            <td><a href="${w.link}" target="_blank" style="color:#80c0ff;">${w.link}</a></td>
        </tr>`;
    }).join('');
    const current = Number(worldCurrentPage);
    const total = Number(worldTotalPages);
    worldPaginationDiv.innerHTML = `<button ${current <= 1 ? 'disabled' : ''} onclick="worldPrevPage()">Prev</button>
        <span>Page ${current} of ${total}</span>
        <button ${current >= total ? 'disabled' : ''} onclick="worldNextPage()">Next</button>`;
}

function loadWorlds() {
    const q = worldSearchInput.value;
    const endpoint = q
        ? `worlds/search?q=${encodeURIComponent(q)}&page=${worldCurrentPage}`
        : `worlds?page=${worldCurrentPage}`;
    sendAdminRequest(endpoint, data => {
        if (data.invalid_page) {
            worldCurrentPage = 1;
            loadWorlds();
            return;
        }
        worldTotalPages = data.totalPages;
        renderWorlds(data);
    }, { get: true });
}

function worldPrevPage() { if (worldCurrentPage > 1) { worldCurrentPage--; loadWorlds(); } }
function worldNextPage() { if (worldCurrentPage < worldTotalPages) { worldCurrentPage++; loadWorlds(); } }

worldSearchInput.addEventListener('input', () => { worldCurrentPage = 1; loadWorlds(); });
worldRefreshBtn.addEventListener('click', () => loadWorlds());
loadWorlds();

function loadAccounts() {
    const q = accSearchInput.value;
    const endpoint = q ? `user/search?q=${encodeURIComponent(q)}&page=${accCurrentPage}`
        : `user/oldest?page=${accCurrentPage}`;
    sendAdminRequest(endpoint, data => {
        if (!data || !data.data || data.data.length === 0) {
            accTableBody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No users found.</td></tr>';
            accPaginationDiv.innerHTML = '';
            return;
        }
        accTotalPages = data.totalPages;
        accTableBody.innerHTML = data.data.map(u => `<tr>
            <td>${u.user}</td>
            <td>${u.id}</td>
            <td style="text-align:center;">${u.online ? 'Yes' : 'No'}</td>
            <td>${u.where || '-'}</td>
            <td>${formatUnixTime(Math.floor(new Date(u.date_joined).getTime() / 1000))}</td>
        </tr>`).join('');
        const current = Number(accCurrentPage);
        const total = Number(accTotalPages);
        accPaginationDiv.innerHTML = `<button ${current <= 1 ? 'disabled' : ''} onclick="accPrevPage()">Prev</button>
            <span>Page ${current} of ${total}</span>
            <button ${current >= total ? 'disabled' : ''} onclick="accNextPage()">Next</button>`;
    }, { get: true });
}
function accPrevPage() { if (accCurrentPage > 1) { accCurrentPage--; loadAccounts(); } }
function accNextPage() { if (accCurrentPage < accTotalPages) { accCurrentPage++; loadAccounts(); } }
accSearchInput.addEventListener('input', () => { accCurrentPage = 1; loadAccounts(); });
accRefreshBtn.addEventListener('click', () => loadAccounts());
loadAccounts();

function loadConnections() {
    const q = connSearchInput.value;
    const endpoint = q ? `active/search?q=${encodeURIComponent(q)}&page=${connCurrentPage}`
        : `active?page=${connCurrentPage}`;
    sendAdminRequest(endpoint, data => {
        if (!data || !data.data || data.data.length === 0) {
            connTableBody.innerHTML = '<tr><td colspan="10" style="text-align:center;">No connections found.</td></tr>';
            connPaginationDiv.innerHTML = '';
            return;
        }
        connTotalPages = data.totalPages;
        connTableBody.innerHTML = data.data.map(c => {
            const worldsLink = `<a href="#" class="connWorldLink">Worlds...</a>`
            return `<tr>
        <td>${c.username}</td>
        <td>${c.id}</td>
        <td style="text-align:center;">${c.isAdmin ? 'Yes' : 'No'}</td>
        <td style="text-align:center;">${c.authenticated ? 'Yes' : 'No'}</td>
        <td>${worldsLink}</td>
        <td>${c.xy.x},${c.xy.y}</td>
        <td style="text-align:center;">${c.anonymous ? 'Yes' : 'No'}</td>
        <td>-</td>
        <td>${c.color_index}</td>
        <td>${c.where || '-'}</td>
    </tr>`;
        }).join('');



        const current = Number(connCurrentPage);
        const total = Number(connTotalPages);
        connPaginationDiv.innerHTML = `<button ${current <= 1 ? 'disabled' : ''} onclick="connPrevPage()">Prev</button>
            <span>Page ${current} of ${total}</span>
            <button ${current >= total ? 'disabled' : ''} onclick="connNextPage()">Next</button>`;
    }, { get: true });
}
function connPrevPage() { if (connCurrentPage > 1) { connCurrentPage--; loadConnections(); } }
function connNextPage() { if (connCurrentPage < connTotalPages) { connCurrentPage++; loadConnections(); } }
connSearchInput.addEventListener('input', () => { connCurrentPage = 1; loadConnections(); });
connRefreshBtn.addEventListener('click', () => loadConnections());
loadConnections();
document.querySelector('#connectionsTable').addEventListener('click', (e) => {
    if (e.target.classList.contains('connWorldLink')) {
        e.preventDefault();
        const tr = e.target.closest('tr');
        const username = tr.children[0].innerText;

        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
        const wtabb = document.querySelector('[data-tab="Worlds"]');
        const worldsTab = document.getElementById('Worlds');
        worldsTab.classList.add('active');
        wtabb.classList.add('active')

        worldSearchInput.value = username;
        worldCurrentPage = 1;
        loadWorlds();
    }
});
ids = []
const targetSelect = document.getElementById('targetId');

function loadActiveUsers() {
    const currentValue = targetSelect.value; // remember selection

    sendAdminRequest('active/all', data => {
        if (!data || !data.data || data.data.length === 0) return;

        targetSelect.innerHTML = '<option value="">-- Select Target --</option><option value="all">Broadcast</option>';

        data.data.forEach(user => {
            const option = document.createElement('option');
            option.value = user.id;
            option.textContent = user.username === "-" ? user.id : user.username;
            targetSelect.appendChild(option);
        });

        if (currentValue) targetSelect.value = currentValue;
    });
}

targetSelect.addEventListener('click', () => {
    loadActiveUsers();
});


require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.43.0/min/vs' } });
require(['vs/editor/editor.main'], function () {
    const editor = monaco.editor.create(document.getElementById('remoteEditor'), {
        value: "// script goes here...\n",
        language: 'javascript',
        automaticLayout: true,
        theme: "vs-dark",
    });


    monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
        noSemanticValidation: false, // still check types
        noSyntaxValidation: false,   // still check syntax
        diagnosticCodesToIgnore: [6133, 7027, 2304] // 2304 = cannot find name (undefined)
    });


    const statusDiv = document.getElementById('remoteStatus');

    document.getElementById('executeScript').addEventListener('click', async () => {
        const script = editor.getValue();
        const targetId = document.getElementById('targetId').value;

        if (!targetId) {
            statusDiv.style.color = 'red';
            statusDiv.innerText = "Please select a Target ID!";
            return;
        }

        statusDiv.style.color = 'black';
        statusDiv.innerText = "Sending script...";
        const isBroadcast = targetId === "all";
        const endpoint = "remote";

        await sendAdminRequest("remote", (res) => {
            if (res.success) {
                statusDiv.style.color = 'green';
                statusDiv.innerText = isBroadcast
                    ? "Broadcast delivered successfully!"
                    : "Script delivered successfully!";
            } else {
                statusDiv.style.color = 'red';
                statusDiv.innerText = "Failed to send script: " + (res.error || JSON.stringify(res));
            }
        }, {
            body: isBroadcast ? { id: "all", script } : { id: targetId, script }
        });
    });

    document.getElementById('clearScript').addEventListener('click', () => {
        editor.setValue('');
        statusDiv.innerText = '';
    });

    document.getElementById('loadScript').addEventListener('click', () => {
        const saved = localStorage.getItem('remoteScript');
        if (saved) {
            editor.setValue(saved);
            statusDiv.style.color = 'green';
            statusDiv.innerText = "Script loaded from local storage.";
        } else {
            statusDiv.style.color = 'red';
            statusDiv.innerText = "No saved script found.";
        }
    });

    document.getElementById('saveScript').addEventListener('click', () => {
        const script = editor.getValue();
        localStorage.setItem('remoteScript', script);
        statusDiv.style.color = 'green';
        statusDiv.innerText = "Script saved locally.";
    });

    document.getElementById('fileInput').addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = e => {
            editor.setValue(e.target.result);
            statusDiv.style.color = 'green';
            statusDiv.innerText = `Loaded script from file: ${file.name}`;
        };
        reader.onerror = e => {
            statusDiv.style.color = 'red';
            statusDiv.innerText = "Failed to read file.";
        };
        reader.readAsText(file);
    });
});
sendAdminRequest('uptime', d => {
    const now = new Date();
    const started = new Date(now.getTime() - d.uptime * 1000);

    const months = [
        'January','February','March','April','May','June',
        'July','August','September','October','November','December'
    ];

    const month = months[started.getMonth()];
    const day = started.getDate();
    const year = started.getFullYear();

    let hours = started.getHours();
    const minutes = started.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12 || 12; // convert 0-23 to 12-hour format

    document.getElementById('started').innerText =
        `${month} ${day}, ${year}, ${hours}:${minutes} ${ampm}`;
}, { get: true });

async function refreshWhitelist() {
    sendAdminRequest("whitelist/list", (data) => {
        const enabled = data[0];
        const users = data[1];
        document.getElementById("enable").checked = enabled;

        const fieldset = document.querySelector("#Settings fieldset");
        fieldset.innerHTML = "";

        users.forEach(user => {
            const wrapper = document.createElement("div");
            wrapper.style.margin = "4px 0";

            const btn = document.createElement("button");
            btn.innerText = "❌";
            btn.style.marginLeft = "8px";
            btn.onclick = () => removeUser(user);

            const label = document.createElement("span");
            label.textContent = user;

            wrapper.appendChild(label);
            wrapper.appendChild(btn);
            fieldset.appendChild(wrapper);
        });
    }, { get: true });
}
function toggleWhitelist(state) {
    sendAdminRequest("whitelist/toggle", () => refreshWhitelist(), { body: { toggle: state } });
}

function addUser() {
    const user = document.getElementById("whadduser").value.trim();
    if (!user) return;
    sendAdminRequest("whitelist/add", () => {
        document.getElementById("whadduser").value = "";
        refreshWhitelist();
    }, { body: { user } });
}

function removeUser(user) {
    sendAdminRequest("whitelist/remove", () => refreshWhitelist(), { body: { user } });
}

document.getElementById("enable").addEventListener("change", e => toggleWhitelist(e.target.checked));
document.getElementById("whadduser").addEventListener("keydown", e => {
    if (e.key === "Enter") addUser();
});

// initial load
refreshWhitelist();

