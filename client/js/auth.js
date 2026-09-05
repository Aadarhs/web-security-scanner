let authToken = localStorage.getItem('authToken');
let currentUser = null;

document.addEventListener('DOMContentLoaded', () => {
  initAuth();
  initLoginModal();
});

function initAuth() {
  if (authToken) {
    verifyAndRestoreSession();
  }
  updateAuthUI();
}

async function verifyAndRestoreSession() {
  try {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (res.ok) {
      currentUser = await res.json();
      updateAuthUI();
      if (currentUser.role === 'admin') {
        ['adminNavLink', 'adminNavLinkMobile'].forEach((id) => {
          const adminLink = document.getElementById(id);
          if (adminLink) adminLink.style.display = '';
        });
      }
    } else {
      localStorage.removeItem('authToken');
      authToken = null;
      currentUser = null;
      updateAuthUI();
    }
  } catch {
  }
}

function updateAuthUI() {
  const loginBtn = document.getElementById('loginBtn');
  const userInfo = document.getElementById('userInfo');
  const userName = document.getElementById('userName');

  if (currentUser && authToken) {
    loginBtn.style.display = 'none';
    userInfo.style.display = 'flex';
    if (userName) userName.textContent = currentUser.name || 'Admin';
  } else {
    loginBtn.style.display = '';
    userInfo.style.display = 'none';
  }
}

function initLoginModal() {
  const modal = document.getElementById('loginModal');
  const loginBtn = document.getElementById('loginBtn');
  const closeBtn = document.getElementById('loginModalClose');
  const submitBtn = document.getElementById('loginSubmitBtn');
  const emailInput = document.getElementById('loginEmail');
  const passwordInput = document.getElementById('loginPassword');
  const errorDiv = document.getElementById('loginError');
  const logoutBtn = document.getElementById('logoutBtn');

  // Open modal
  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      modal.style.display = 'flex';
      emailInput.value = '';
      passwordInput.value = '';
      errorDiv.style.display = 'none';
      emailInput.focus();
    });
  }

  // Close modal
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      modal.style.display = 'none';
    });
  }

  // Close on overlay click
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.style.display = 'none';
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') modal.style.display = 'none';
  });

  // Enter to submit
  passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitBtn.click();
  });
  emailInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') passwordInput.focus();
  });

  // Login submit
  submitBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
      errorDiv.textContent = 'Email and password are required';
      errorDiv.style.display = 'block';
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in...';
    errorDiv.style.display = 'none';

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok && data.token) {
        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('authToken', authToken);
        updateAuthUI();
        modal.style.display = 'none';
        showNotification('Logged in as ' + (data.user?.name || email), 'success');
      } else {
        errorDiv.textContent = data.error || 'Invalid credentials';
        errorDiv.style.display = 'block';
      }
    } catch (err) {
      errorDiv.textContent = 'Connection failed: ' + err.message;
      errorDiv.style.display = 'block';
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign In';
    }
  });

  // Logout
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      authToken = null;
      currentUser = null;
      localStorage.removeItem('authToken');
      updateAuthUI();
      showNotification('Logged out', 'info');
    });
  }
}

// Helper to get auth headers for API calls
function getAuthHeaders() {
  if (authToken) {
    return { 'Authorization': `Bearer ${authToken}` };
  }
  return {};
}
