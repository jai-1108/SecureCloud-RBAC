document.addEventListener('DOMContentLoaded', () => {
  // Navigation Logic
  const navItems = document.querySelectorAll('.nav-item');
  const views = document.querySelectorAll('.view');
  const pageTitle = document.getElementById('page-title');

  // Mapping target IDs to Page Titles
  const titleMap = {
    'dashboard-view': 'Dashboard Overview',
    'roles-view': 'Role Hierarchy Management',
    'users-view': 'User & Identity Management',
    'compliance-view': 'Compliance & Audits',
    'simulator-view': 'Access Simulator Testing'
  };

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      // Remove active class from all nav items
      navItems.forEach(nav => nav.classList.remove('active'));
      
      // Add active class to clicked nav item
      item.classList.add('active');

      // Get target view id
      const targetId = item.getAttribute('data-target');

      // Update Header Title
      pageTitle.textContent = titleMap[targetId] || 'RBAC Dashboard';

      // Hide all views
      views.forEach(view => {
        view.classList.remove('active');
      });

      // Show target view
      const targetView = document.getElementById(targetId);
      if (targetView) {
        targetView.classList.add('active');
      }
    });
  });

  // Tree Toggle Logic for Role Hierarchy
  const treeToggles = document.querySelectorAll('.tree-toggle');
  
  treeToggles.forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation(); // Prevent row click events if any
      const icon = toggle.querySelector('i');
      
      // The ul.tree-group is the next sibling element of the tree-node div
      const parentLi = toggle.closest('li');
      const childrenGroup = parentLi.querySelector('.tree-group');

      if (childrenGroup) {
        if (childrenGroup.style.display === 'none') {
          childrenGroup.style.display = 'block';
          icon.classList.remove('fa-chevron-right');
          icon.classList.add('fa-chevron-down');
        } else {
          childrenGroup.style.display = 'none';
          icon.classList.remove('fa-chevron-down');
          icon.classList.add('fa-chevron-right');
        }
      }
    });
  });

  // Add click handlers for escalation requests
  const approveBtns = document.querySelectorAll('.btn-icon.approve');
  const denyBtns = document.querySelectorAll('.btn-icon.deny');

  approveBtns.forEach(btn => {
    btn.addEventListener('click', function() {
      const actionItem = this.closest('.action-item');
      actionItem.style.opacity = '0.5';
      setTimeout(() => {
        actionItem.innerHTML = `<div class="action-info"><span class="status-text text-teal"><i class="fa-solid fa-check"></i> Approved & Applied</span></div>`;
        actionItem.style.opacity = '1';
      }, 300);
    });
  });

  denyBtns.forEach(btn => {
    btn.addEventListener('click', function() {
      const actionItem = this.closest('.action-item');
      actionItem.style.opacity = '0.5';
      setTimeout(() => {
        actionItem.innerHTML = `<div class="action-info"><span class="status-text text-danger"><i class="fa-solid fa-ban"></i> Request Denied</span></div>`;
        actionItem.style.opacity = '1';
      }, 300);
    });
  });

  // --- Access Simulator Logic ---
  
  // 1. Mock Database of Roles and their permissions
  const mockPermissionsDb = {
    'SuperAdmin': ['read_user', 'write_user', 'delete_user', 'read_salary', 'write_salary', 'assign_role', 'read_audit', 'write_config', 'delete_config'],
    'Admin': ['read_user', 'write_user', 'read_salary', 'assign_role', 'read_audit', 'write_config'],
    'HR_Manager': ['read_user', 'write_user', 'read_salary', 'write_salary'],
    'Developer': ['read_user', 'read_audit', 'write_config'],
    'Auditor': ['read_user', 'read_audit', 'read_salary'],
    'Guest': ['read_user']
  };

  const roleSelect = document.getElementById('sim-role-select');
  const permissionsList = document.getElementById('sim-permissions-list');
  const protectedForm = document.getElementById('protected-form');

  function updateSimulator(role) {
    if (!roleSelect || !permissionsList || !protectedForm) return;

    // Get permissions for role (or empty array if not found)
    const perms = mockPermissionsDb[role] || [];

    // Render permission badges
    permissionsList.innerHTML = '';
    if (perms.length === 0) {
      permissionsList.innerHTML = '<span class="text-dim">No permissions</span>';
    } else {
      perms.forEach(p => {
        const badge = document.createElement('span');
        badge.className = 'perm-badge';
        badge.textContent = p;
        permissionsList.appendChild(badge);
      });
    }

    // Enforce form constraints
    // Find all inputs, selects, textareas, and buttons in the form that have a data-requires attribute
    const restrictedElements = protectedForm.querySelectorAll('[data-requires]');
    
    restrictedElements.forEach(el => {
      const reqPerm = el.getAttribute('data-requires');
      const hasAccess = perms.includes(reqPerm);
      const formGroup = el.closest('.form-group') || el.parentElement;

      if (hasAccess) {
        // Unlock
        el.disabled = false;
        formGroup.classList.remove('input-locked');
      } else {
        // Lock
        el.disabled = true;
        formGroup.classList.add('input-locked');
      }
    });
  }

  // Event listener for dropdown change
  if (roleSelect) {
    roleSelect.addEventListener('change', (e) => {
      updateSimulator(e.target.value);
    });

    // Initialize with default selected role
    updateSimulator(roleSelect.value);
  }

});
