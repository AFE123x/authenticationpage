// API configuration
const API_BASE = '';
// State
let documents = [];
let currentUsername = null;
let currentUserRole = null;
let selectedDocId = null;
// Initialize the page
async function initializePage() {
    try {
        // Load username and role
        const userData = await fetchUser();
        if (userData) {
            currentUsername = userData.username;
            currentUserRole = userData.role;
            document.getElementById('username-badge').textContent = `👤 ${currentUsername} (${currentUserRole})`;

            if (currentUserRole === 'Admin') {
                document.getElementById('adminSection').style.display = 'block';
                loadAdminUserList();
            }
        } else {
            window.location.href = '/';
        }
        // Load documents
        await loadDocuments();
        // Setup modals
        setupModal();
        setupAuditModal();

        // Setup update input
        document.getElementById('updateVersionInput').addEventListener('change', handleUpdateFileSelect);
    } catch (error) {
        showAlert('Error initializing page: ' + error.message, 'error');
    }
}

// Setup Modal Events
function setupModal() {
    const modal = document.getElementById('shareModal');
    const closeBtn = document.getElementById('closeModal');
    const cancelBtn = document.getElementById('cancelShare');
    const confirmBtn = document.getElementById('confirmShare');
    const closeModal = () => {
        modal.style.display = 'none';
        document.getElementById('shareTargetUser').value = '';
        selectedDocId = null;
    };
    closeBtn.onclick = closeModal;
    cancelBtn.onclick = closeModal;
    confirmBtn.onclick = async () => {
        const targetUser = document.getElementById('shareTargetUser').value.trim();
        const role = document.getElementById('shareRole').value;
        if (!targetUser) {
            showAlert('Please enter a target username', 'error');
            return;
        }
        if (targetUser === currentUsername) {
            showAlert('You cannot share a document with yourself', 'error');
            return;
        }
        try {
            const response = await fetch(`${API_BASE}/api/documents/${selectedDocId}/share`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target_username: targetUser,
                    role: role
                }),
                credentials: 'include'
            });
            if (response.ok) {
                showAlert(`Document shared with ${targetUser} successfully!`, 'success');
                document.getElementById('shareTargetUser').value = '';
                await loadDocuments();
                renderAccessList(); // Re-render the list in modal
            } else {
                const error = await response.text();
                showAlert('Sharing failed: ' + error, 'error');
            }
        } catch (error) {
            showAlert('Error sharing document: ' + error.message, 'error');
        }
    };
}

// Setup Audit Modal
function setupAuditModal() {
    const modal = document.getElementById('auditModal');
    const closeBtn = document.getElementById('closeAuditModal');
    const closeBtnFooter = document.getElementById('closeAuditBtn');

    const closeModal = () => {
        modal.style.display = 'none';
    };

    closeBtn.onclick = closeModal;
    closeBtnFooter.onclick = closeModal;
}

// Global click handler for modals
window.addEventListener('click', (event) => {
    const shareModal = document.getElementById('shareModal');
    const auditModal = document.getElementById('auditModal');
    if (event.target === shareModal) {
        shareModal.style.display = 'none';
        document.getElementById('shareTargetUser').value = '';
        selectedDocId = null;
    } else if (event.target === auditModal) {
        auditModal.style.display = 'none';
    }
});

// Render Access List in Modal
function renderAccessList() {
    const container = document.getElementById('currentAccessList');
    const doc = documents.find(d => d.id === selectedDocId);
    if (!doc || !doc.permissions || Object.keys(doc.permissions).length === 0) {
        container.innerHTML = '<div style="color: #999; font-style: italic; font-size: 14px;">No other users have access yet.</div>';
        return;
    }
    container.innerHTML = Object.entries(doc.permissions).map(([user, role]) => `
        <div class="access-item">
            <div class="access-user-info">
                <span class="access-username">${escapeHtml(user)}</span>
                <span class="access-role">${escapeHtml(role)}</span>
            </div>
            <button class="btn btn-revoke" data-username="${escapeHtml(user)}">Revoke</button>
        </div>
    `).join('');

    // Attach event listeners to revoke buttons
    container.querySelectorAll('.btn-revoke').forEach(btn => {
        btn.onclick = () => {
            const username = btn.getAttribute('data-username');
            revokeAccess(username);
        };
    });
}

// Revoke Access
async function revokeAccess(targetUser) {
    if (!confirm(`Are you sure you want to remove access for ${targetUser}?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/documents/${selectedDocId}/share`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target_username: targetUser
            }),
            credentials: 'include'
        });
        if (response.ok) {
            showAlert(`Access revoked for ${targetUser}`, 'success');
            await loadDocuments();
            renderAccessList();
        } else {
            const error = await response.text();
            showAlert('Revocation failed: ' + error, 'error');
        }
    } catch (error) {
        showAlert('Error revoking access: ' + error.message, 'error');
    }
}

// Fetch current user data
async function fetchUser() {
    try {
        const response = await fetch(`${API_BASE}/api/user`, {
            credentials: 'include'
        });
        if (response.ok) {
            return await response.json();
        }
        return null;
    } catch (error) {
        console.error('Error fetching user:', error);
        return null;
    }
}

// Admin: Load all users
async function loadAdminUserList() {
    try {
        const response = await fetch(`${API_BASE}/api/admin/users`, {
            credentials: 'include'
        });
        if (response.ok) {
            const users = await response.json();
            renderAdminUserList(users);
        }
    } catch (error) {
        console.error('Error loading admin user list:', error);
    }
}

function renderAdminUserList(users) {
    const body = document.getElementById('userListBody');
    body.innerHTML = users.map(user => {
        const isSelf = user.username === currentUsername;
        return `
            <tr>
                <td>${escapeHtml(user.username)} ${isSelf ? '<span style="font-size: 10px; color: #999;">(You)</span>' : ''}</td>
                <td>${escapeHtml(user.email)}</td>
                <td>${escapeHtml(user.role)}</td>
                <td>
                    <select class="role-select" 
                            ${isSelf ? 'disabled title="You cannot change your own role"' : ''}
                            onchange="updateUserRole('${escapeHtml(user.username)}', this.value)">
                        <option value="User" ${user.role === 'User' ? 'selected' : ''}>User</option>
                        <option value="Admin" ${user.role === 'Admin' ? 'selected' : ''}>Admin</option>
                        <option value="Guest" ${user.role === 'Guest' ? 'selected' : ''}>Guest</option>
                    </select>
                </td>
            </tr>
        `;
    }).join('');
}

async function updateUserRole(username, newRole) {
    try {
        const response = await fetch(`${API_BASE}/api/admin/users/${username}/role`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: newRole }),
            credentials: 'include'
        });
        if (response.ok) {
            showAlert(`Role for ${username} updated to ${newRole}`, 'success');
            if (username === currentUsername) {
                // If we changed our own role, refresh to see changes
                location.reload();
            } else {
                loadAdminUserList();
            }
        } else {
            const error = await response.text();
            showAlert('Update failed: ' + error, 'error');
        }
    } catch (error) {
        showAlert('Error updating role: ' + error.message, 'error');
    }
}
// Load documents list
async function loadDocuments() {
    try {
        const response = await fetch(`${API_BASE}/api/documents`, {
            credentials: 'include'
        });
        if (response.ok) {
            documents = await response.json();
            renderDocuments();
            updateStats();
        } else if (response.status === 401) {
            window.location.href = '/';
        }
    } catch (error) {
        showAlert('Error loading documents: ' + error.message, 'error');
    }
}
// Render documents list
function renderDocuments() {
    const listContainer = document.getElementById('documentsList');
    if (documents.length === 0) {
        listContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📭</div>
                <div class="empty-state-text">No documents uploaded yet. Start by uploading your first document!</div>
            </div>
        `;
        return;
    }
    const documentsHTML = documents.map(doc => {
        const timestamp = doc.uploaded_at || doc.uploadedAt || doc.created_at;
        const date = new Date(timestamp).toLocaleDateString();
        const size = formatFileSize(doc.size);
        const isOwner = doc.uploaded_by === currentUsername;
        // For non-owners, permissions map only contains their own entry
        const myPerms = doc.permissions || {};
        const isEditor = myPerms[currentUsername] === 'editor';
        const version = doc.version || 1;
        return `
            <div class="document-item">
                <div class="document-info">
                    <div class="document-name">📄 ${escapeHtml(doc.filename)} <span style="font-size: 11px; background: #e9ecef; padding: 2px 6px; border-radius: 4px; margin-left: 5px;">v${version}</span></div>
                    <div class="document-meta">
                        <span class="document-size">${size}</span>
                        <span class="document-date">Uploaded on ${date}</span>
                        ${!isOwner ? `<span style="margin-left: 10px; color: #667eea; font-weight: 600;">(Shared by ${escapeHtml(doc.uploaded_by)})</span>` : ''}
                    </div>
                </div>
                <div class="document-actions">
                    <button class="btn btn-download" data-id="${escapeHtml(doc.id)}" data-filename="${escapeHtml(doc.filename)}">Download</button>
                    ${isOwner || isEditor ? `<button class="btn btn-update" data-id="${escapeHtml(doc.id)}">Update</button>` : ''}
                    ${isOwner ? `
                        <button class="btn btn-audit" data-id="${escapeHtml(doc.id)}">Audit Log</button>
                        <button class="btn btn-share" data-id="${escapeHtml(doc.id)}">Share</button>
                        <button class="btn btn-delete" data-id="${escapeHtml(doc.id)}">Delete</button>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
    listContainer.innerHTML = documentsHTML;

    // Attach event listeners
    listContainer.querySelectorAll('.btn-download').forEach(btn => {
        btn.addEventListener('click', () => {
            const docId = btn.getAttribute('data-id');
            const filename = btn.getAttribute('data-filename');
            downloadDocument(docId, filename);
        });
    });

    listContainer.querySelectorAll('.btn-update').forEach(btn => {
        btn.addEventListener('click', () => {
            selectedDocId = btn.getAttribute('data-id');
            document.getElementById('updateVersionInput').click();
        });
    });

    listContainer.querySelectorAll('.btn-audit').forEach(btn => {
        btn.addEventListener('click', () => {
            const docId = btn.getAttribute('data-id');
            showAuditLog(docId);
        });
    });

    listContainer.querySelectorAll('.btn-share').forEach(btn => {
        btn.addEventListener('click', () => {
            selectedDocId = btn.getAttribute('data-id');
            document.getElementById('shareModal').style.display = 'block';
            renderAccessList();
        });
    });

    listContainer.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', () => {
            const docId = btn.getAttribute('data-id');
            deleteDocument(docId);
        });
    });
}
// Show Audit Log
async function showAuditLog(docId) {
    const container = document.getElementById('auditLogContent');
    container.innerHTML = 'Loading activity log...';
    document.getElementById('auditModal').style.display = 'block';

    try {
        const response = await fetch(`${API_BASE}/api/documents/${docId}/audit`, {
            credentials: 'include'
        });

        if (response.ok) {
            const auditLog = await response.json();
            if (!auditLog || auditLog.length === 0) {
                container.innerHTML = 'No activity recorded yet.';
            } else {
                container.innerHTML = auditLog.map(entry => `
                    <div class="audit-entry">${escapeHtml(entry)}</div>
                `).join('');
            }
        } else {
            const error = await response.text();
            container.innerHTML = `<div style="color: #dc3545;">Error loading audit log: ${escapeHtml(error)}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div style="color: #dc3545;">Error: ${escapeHtml(error.message)}</div>`;
    }
}

// Handle update file select
function handleUpdateFileSelect(e) {
    const file = e.target.files[0];
    if (file && selectedDocId) {
        updateDocument(selectedDocId, file);
    }
}

// Update document
async function updateDocument(docId, file) {
    const maxSize = 100 * 1024 * 1024; // 100MB limit
    if (file.size > maxSize) {
        showAlert(`File too large. Maximum size is ${formatFileSize(maxSize)}.`, 'error');
        document.getElementById('updateVersionInput').value = '';
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    const uploadProgress = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const uploadStatus = document.getElementById('uploadStatus');
    uploadProgress.style.display = 'block';
    uploadStatus.textContent = 'Updating...';

    try {
        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressFill.style.width = percentComplete + '%';
                uploadStatus.textContent = `Updating: ${percentComplete.toFixed(0)}%`;
            }
        });
        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                showAlert(`Document updated successfully!`, 'success');
                loadDocuments();
            } else {
                showAlert(xhr.responseText || 'Update failed', 'error');
            }
            uploadProgress.style.display = 'none';
            document.getElementById('updateVersionInput').value = '';
        });
        xhr.addEventListener('error', () => {
            showAlert('Update failed: ' + xhr.statusText, 'error');
            uploadProgress.style.display = 'none';
            document.getElementById('updateVersionInput').value = '';
        });
        xhr.addEventListener('abort', () => {
            showAlert('Update cancelled', 'info');
            uploadProgress.style.display = 'none';
            document.getElementById('updateVersionInput').value = '';
        });
        xhr.open('POST', `${API_BASE}/api/documents/${docId}/update`, true);
        xhr.withCredentials = true;
        xhr.send(formData);
    } catch (error) {
        showAlert('Error updating document: ' + error.message, 'error');
        uploadProgress.style.display = 'none';
    }
}

// Update statistics
function updateStats() {
    const totalDocs = documents.length;
    const totalBytes = documents.reduce((sum, doc) => sum + (doc.size || 0), 0);
    const totalSize = formatFileSize(totalBytes);
    // Count documents uploaded in last 24 hours
    const now = Date.now();
    const oneDayMs = 24 * 60 * 60 * 1000;
    const recentCount = documents.filter(doc => {
        const timestamp = doc.uploaded_at || doc.uploadedAt || doc.created_at;
        const uploadTime = new Date(timestamp).getTime();
        return (now - uploadTime) < oneDayMs;
    }).length;
    document.getElementById('totalDocuments').textContent = totalDocs;
    document.getElementById('totalSize').textContent = totalSize;
    document.getElementById('recentCount').textContent = recentCount;
}
// Setup upload area
function setupUploadArea() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    // Click to upload
    uploadArea.addEventListener('click', (e) => {
        // Prevent duplicate click if clicking on the label or input directly
        if (e.target !== fileInput && !e.target.closest('.file-input-label')) {
            fileInput.click();
        }
    });
    // Drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelect();
        }
    });
    // File input change
    fileInput.addEventListener('change', handleFileSelect);
}
// Handle file selection
function handleFileSelect() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (file) {
        uploadFile(file);
    }
}
// Upload file
async function uploadFile(file) {
    const maxSize = 100 * 1024 * 1024; // 100MB limit
    if (file.size > maxSize) {
        showAlert(`File too large. Maximum size is ${formatFileSize(maxSize)}.`, 'error');
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    const uploadProgress = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const uploadStatus = document.getElementById('uploadStatus');
    uploadProgress.style.display = 'block';
    uploadStatus.textContent = 'Uploading...';
    try {
        const xhr = new XMLHttpRequest();
        // Track upload progress
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressFill.style.width = percentComplete + '%';
                uploadStatus.textContent = `Uploading: ${percentComplete.toFixed(0)}%`;
            }
        });
        xhr.addEventListener('load', async () => {
            if (xhr.status === 200 || xhr.status === 201) {
                uploadStatus.textContent = 'Upload complete!';
                progressFill.style.width = '100%';
                showAlert(`Document "${file.name}" uploaded successfully!`, 'success');
                // Reset file input
                document.getElementById('fileInput').value = '';
                // Reload documents after a short delay
                setTimeout(() => {
                    uploadProgress.style.display = 'none';
                    loadDocuments();
                }, 1000);
            } else {
                const errorMessage = xhr.responseText || 'Upload failed';
                showAlert(errorMessage, 'error');
                uploadProgress.style.display = 'none';
            }
        });
        xhr.addEventListener('error', () => {
            showAlert('Upload failed: ' + xhr.statusText, 'error');
            uploadProgress.style.display = 'none';
        });
        xhr.addEventListener('abort', () => {
            showAlert('Upload cancelled', 'info');
            uploadProgress.style.display = 'none';
        });
        xhr.open('POST', `${API_BASE}/api/documents/upload`, true);
        xhr.withCredentials = true;
        xhr.send(formData);
    } catch (error) {
        showAlert('Error uploading file: ' + error.message, 'error');
        uploadProgress.style.display = 'none';
    }
}
// Download document
async function downloadDocument(docId, filename) {
    try {
        const link = document.createElement('a');
        link.href = `${API_BASE}/api/documents/${docId}/download`;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        // Reload documents after a short delay to see the download event in audit log
        setTimeout(loadDocuments, 2000);
    } catch (error) {
        showAlert('Error downloading file: ' + error.message, 'error');
    }
}
// Delete document
async function deleteDocument(docId) {
    if (!confirm('Are you sure you want to delete this document? This action cannot be undone.')) {
        return;
    }
    try {
        const response = await fetch(`${API_BASE}/api/documents/${docId}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        if (response.ok) {
            showAlert('Document deleted successfully', 'success');
            loadDocuments();
        } else if (response.status === 401) {
            window.location.href = '/';
        } else {
            const errorMessage = await response.text();
            showAlert(errorMessage || 'Failed to delete document', 'error');
        }
    } catch (error) {
        showAlert('Error deleting document: ' + error.message, 'error');
    }
}
// Show alert
function showAlert(message, type = 'info') {
    const alertsContainer = document.getElementById('alerts');
    const alertId = 'alert-' + Date.now();
    const alertHTML = `
        <div class="alert alert-${type}" id="${alertId}">
            ${escapeHtml(message)}
        </div>
    `;
    alertsContainer.insertAdjacentHTML('beforeend', alertHTML);
    // Auto-remove after 5 seconds
    setTimeout(() => {
        const alert = document.getElementById(alertId);
        if (alert) {
            alert.remove();
        }
    }, 5000);
}
// Utility functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}
// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setupUploadArea();
    initializePage();
});
// Refresh documents every 30 seconds
setInterval(loadDocuments, 30000);
