/* ===== HAMBURGER / SIDE DRAWER (robust) ===== */
(function() {
  // Find the hamburger button (support several class/id variants)
  const hamburgerBtn =
    document.getElementById('hamburgerBtn') ||
    document.querySelector('.hamburger') ||
    document.querySelector('.hamburger-btn');

  // Support two markup styles: "sideDrawer" (legacy) or "mobileMenu" (templates)
  let sideDrawer = document.getElementById('sideDrawer') || document.getElementById('mobileMenu');

  // Overlay and close button (may be absent)
  let navOverlay = document.getElementById('navOverlay');
  const drawerClose = document.getElementById('drawerClose') || null;

  // Ensure overlay exists and assign it to navOverlay (fix the original bug)
  if (!navOverlay) {
    const overlay = document.createElement('div');
    overlay.className = 'nav-overlay';
    overlay.id = 'navOverlay';
    document.body.appendChild(overlay);
    navOverlay = overlay;
  }

  function openDrawer() {
    if (sideDrawer) sideDrawer.classList.add('open');
    if (navOverlay) navOverlay.classList.add('active');
    if (hamburgerBtn) {
      // Template CSS toggles `.hamburger.open` (or `.hamburger-btn.open`)
      hamburgerBtn.classList.add('open');
      hamburgerBtn.setAttribute('aria-expanded', 'true');
    }
    document.body.style.overflow = 'hidden'; // prevent background scroll
  }

  function closeDrawer() {
    if (sideDrawer) sideDrawer.classList.remove('open');
    if (navOverlay) navOverlay.classList.remove('active');
    if (hamburgerBtn) {
      hamburgerBtn.classList.remove('open');
      hamburgerBtn.setAttribute('aria-expanded', 'false');
    }
    document.body.style.overflow = '';
  }

  // Hamburger click: toggle
  if (hamburgerBtn) {
    hamburgerBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      if (sideDrawer && sideDrawer.classList.contains('open')) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });
  }

  // Close button (if present)
  if (drawerClose) {
    drawerClose.addEventListener('click', closeDrawer);
  }

  // Overlay click: close
  if (navOverlay) {
    navOverlay.addEventListener('click', closeDrawer);
  }

  // Escape key to close
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && sideDrawer && sideDrawer.classList.contains('open')) {
      closeDrawer();
    }
  });

  // Attach to both drawer-link (old) and mm-link (templates)
  document.querySelectorAll('.drawer-link, .mm-link').forEach(function(link) {
    link.addEventListener('click', function(e) {
      // prevent default if it's an anchor
      if (this.tagName.toLowerCase() === 'a') e.preventDefault();
      // try data attributes used across templates
      const page = this.getAttribute('data-page') || this.dataset.nav;
      if (page && typeof window.navigateTo === 'function') {
        try { navigateTo(page); } catch (err) { /* ignore navigation errors */ }
      }
      closeDrawer();
    });
  });

  // Logout: support drawerLogout (old) or mmLogout (possible alternative)
  const logoutBtn = document.getElementById('drawerLogout') || document.getElementById('mmLogout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function() {
      closeDrawer();
      try {
        if (window.state && state.user && state.user.loggedIn) {
          fetch('/logout', { method: 'POST' }).then(function() {
            state.user.loggedIn = false;
            if (typeof window.syncNavState === 'function') syncNavState();
            if (typeof window.navigateTo === 'function') navigateTo('home');
            if (typeof window.toast === 'function') toast('Logged out.');
          });
        }
      } catch (err) {
        // swallow errors so logout won't break UI
        console.error('Logout handler error', err);
      }
    });
  }

  // Sync drawer state with user (guarded)
  window.syncNavState = function() {
    try {
      const nameEl = document.getElementById('drawerName') || document.getElementById('drawerName') || document.querySelector('.drawer-name');
      const avatarEl = document.getElementById('drawerAvatar') || document.querySelector('.drawer-avatar');
      const statusDot = document.getElementById('statusDot');
      const statusText = document.getElementById('statusText');

      if (window.state && state.user && state.user.loggedIn && state.user.name) {
        if (nameEl) nameEl.textContent = state.user.name;
        if (avatarEl) avatarEl.textContent = state.user.name.charAt(0).toUpperCase();
      } else {
        if (nameEl) nameEl.textContent = 'Guest';
        if (avatarEl) avatarEl.textContent = '🌱';
      }

      const status = (state && state.user && state.user.online_status) ? state.user.online_status : 'online';
      if (statusDot) statusDot.className = 'status-dot ' + status;
      if (statusText) statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    } catch (err) {
      // keep syncNavState safe
      console.error('syncNavState error', err);
    }
  };

  // Initialize
  try {
    if (typeof window.syncNavState === 'function') window.syncNavState();
  } catch (e) { /* ignore */ }

})();
