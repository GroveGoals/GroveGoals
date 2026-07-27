/* ===== HAMBURGER MENU FUNCTIONALITY ===== */
(function() {
  const hamburgerBtn = document.getElementById('hamburgerBtn');
  const sideDrawer = document.getElementById('sideDrawer');
  const navOverlay = document.getElementById('navOverlay');
  const drawerClose = document.getElementById('drawerClose');

  // Create overlay if not present
  if (!navOverlay) {
    const overlay = document.createElement('div');
    overlay.className = 'nav-overlay';
    overlay.id = 'navOverlay';
    document.body.appendChild(overlay);
  }

  function openDrawer() {
    sideDrawer.classList.add('open');
    navOverlay.classList.add('active');
    hamburgerBtn.classList.add('active');
    hamburgerBtn.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden'; // prevent background scroll
  }

  function closeDrawer() {
    sideDrawer.classList.remove('open');
    navOverlay.classList.remove('active');
    hamburgerBtn.classList.remove('active');
    hamburgerBtn.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }

  // Hamburger button click
  if (hamburgerBtn) {
    hamburgerBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      if (sideDrawer.classList.contains('open')) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });
  }

  // Close button
  if (drawerClose) {
    drawerClose.addEventListener('click', closeDrawer);
  }

  // Overlay click (tap outside)
  if (navOverlay) {
    navOverlay.addEventListener('click', closeDrawer);
  }

  // Escape key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && sideDrawer.classList.contains('open')) {
      closeDrawer();
    }
  });

  // Close drawer when a nav link is clicked
  document.querySelectorAll('.drawer-link').forEach(function(link) {
    link.addEventListener('click', function(e) {
      const page = this.getAttribute('data-page');
      if (page) {
        // Navigate to the page/section
        navigateTo(page);
      }
      closeDrawer();
    });
  });

  // Logout button
  const logoutBtn = document.getElementById('drawerLogout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function() {
      closeDrawer();
      if (state.user.loggedIn) {
        fetch('/logout', { method: 'POST' }).then(function() {
          state.user.loggedIn = false;
          syncNavState();
          navigateTo('home');
          toast('Logged out.');
        });
      }
    });
  }

  // Sync drawer state with user
  window.syncNavState = function() {
    const nameEl = document.getElementById('drawerName');
    const avatarEl = document.getElementById('drawerAvatar');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    if (state.user.loggedIn && state.user.name) {
      nameEl.textContent = state.user.name;
      avatarEl.textContent = state.user.name.charAt(0).toUpperCase();
    } else {
      nameEl.textContent = 'Guest';
      avatarEl.textContent = '🌱';
    }

    // Update online status
    const status = state.user.online_status || 'online';
    if (statusDot) {
      statusDot.className = 'status-dot ' + status;
    }
    if (statusText) {
      statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    }
  };

  // Call syncNavState after state changes
  const originalScheduleSave = window.scheduleSaveState;
  window.syncNavState();
})();
