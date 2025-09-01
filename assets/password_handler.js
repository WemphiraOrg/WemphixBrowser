// Self-invoking anonymous function to avoid polluting the global namespace
(function() {
    // 1. Check if the handler is already running
    if (window.wemphixPasswordHandler) return;
    window.wemphixPasswordHandler = true;

    // 2. Constants for IDs and class names
    const GENERATOR_BTN_ID = 'wemphix-gen-btn';
    const AUTOFILL_POPUP_ID = 'wemphix-autofill-popup';
    const AUTOFILL_ITEM_CLASS = 'wemphix-autofill-item';

    // 3. State variables
    let activePasswordField = null; // For the password generator
    let activeUsernameField = null; // For autofill

    // 4. Inject CSS for UI elements
    function injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
            #${GENERATOR_BTN_ID} {
                position: absolute;
                top: 50%;
                right: 5px;
                transform: translateY(-50%);
                cursor: pointer;
                border: none;
                background: transparent;
                font-size: 16px;
                padding: 0 5px;
                z-index: 9999;
                color: #555;
                opacity: 0.7;
                transition: opacity 0.2s;
            }
            #${GENERATOR_BTN_ID}:hover {
                opacity: 1;
            }
            #${AUTOFILL_POPUP_ID} {
                position: absolute;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                z-index: 99999;
                max-height: 200px;
                overflow-y: auto;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                font-size: 14px;
            }
            .${AUTOFILL_ITEM_CLASS} {
                padding: 8px 12px;
                cursor: pointer;
                color: #333;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .${AUTOFILL_ITEM_CLASS}:hover {
                background-color: #f0f0f0;
            }
        `;
        document.head.appendChild(style);
    }

    // 5. UI Functions
    function showGeneratorButton(passwordField) {
        document.getElementById(GENERATOR_BTN_ID)?.remove();
        activePasswordField = passwordField;

        const parent = passwordField.parentNode;
        if (window.getComputedStyle(parent).position === 'static') {
            parent.style.position = 'relative';
        }

        const btn = document.createElement('button');
        btn.id = GENERATOR_BTN_ID;
        btn.innerHTML = '&#x1F511;'; // Key emoji
        btn.title = 'Generar contraseña segura';
        btn.type = 'button';

        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            window.wemphixAPI?.requestPasswordGeneration();
        });
        
        parent.appendChild(btn);
    }

    function showAutofillSuggestions(usernameField, logins) {
        removeAutofillPopup();
        if (!logins || logins.length === 0) return;

        activeUsernameField = usernameField;
        const popup = document.createElement('div');
        popup.id = AUTOFILL_POPUP_ID;

        logins.forEach(username => {
            const item = document.createElement('div');
            item.className = AUTOFILL_ITEM_CLASS;
            item.textContent = username;
            item.title = username;
            item.addEventListener('mousedown', (e) => {
                e.preventDefault();
                fillLogin(username);
            });
            popup.appendChild(item);
        });

        const rect = usernameField.getBoundingClientRect();
        popup.style.left = `${rect.left + window.scrollX}px`;
        popup.style.top = `${rect.bottom + window.scrollY}px`;
        popup.style.minWidth = `${rect.width}px`;

        document.body.appendChild(popup);
    }
    
    function removeAutofillPopup() {
        document.getElementById(AUTOFILL_POPUP_ID)?.remove();
    }

    // 6. Core Logic Functions
    async function fillLogin(username) {
        if (!activeUsernameField) return;
        
        const url = window.location.origin;
        const password = await window.wemphixAPI.getPasswordForLogin(url, username);

        if (password) {
            activeUsernameField.value = username;
            activeUsernameField.dispatchEvent(new Event('input', { bubbles: true }));

            const form = activeUsernameField.form;
            if (form) {
                const passwordField = form.querySelector('input[type="password"]');
                if (passwordField) {
                    passwordField.value = password;
                    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
                    passwordField.focus();
                }
            }
        }
        removeAutofillPopup();
    }

    function handleFormSubmit(event) {
        const form = event.target;
        if (form.tagName !== 'FORM') return;

        const passwordInput = form.querySelector('input[type="password"]');
        if (!passwordInput || !passwordInput.value) return;

        let usernameInput = form.querySelector('input[type="email"], input[type="text"][autocomplete="username"], input[type="text"][name*="user"], input[type="text"][name*="login"], input[type="tel"]');
        if (!usernameInput) {
            const inputs = Array.from(form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])'));
            const passwordIndex = inputs.indexOf(passwordInput);
            if (passwordIndex > 0) usernameInput = inputs[passwordIndex - 1];
        }
        
        const username = usernameInput ? usernameInput.value : '';
        const password = passwordInput.value;
        const url = window.location.origin;

        if (password && window.wemphixAPI) {
            setTimeout(() => window.wemphixAPI.promptToSavePassword(url, username, password), 100);
        }
    }

    // 7. Global Event Listeners (using delegation)
    document.addEventListener('focusin', (event) => {
        const target = event.target;
        if (target.matches('input[type="password"]')) {
            showGeneratorButton(target);
        } else if (target.matches('input[type="email"], input[type="text"][autocomplete="username"], input[type="text"][name*="user"], input[type="text"][name*="login"], input[type="tel"]')) {
            setTimeout(async () => {
                if (document.activeElement === target && window.wemphixAPI) {
                    const logins = await window.wemphixAPI.findLoginsForUrl(window.location.origin);
                    if (logins && logins.length > 0) showAutofillSuggestions(target, logins);
                }
            }, 50);
        }
    });

    document.addEventListener('focusout', (event) => {
        setTimeout(() => {
            if (event.target === activePasswordField && document.activeElement.id !== GENERATOR_BTN_ID) {
                document.getElementById(GENERATOR_BTN_ID)?.remove();
            }
            if (event.target === activeUsernameField && !document.activeElement.classList.contains(AUTOFILL_ITEM_CLASS)) {
                removeAutofillPopup();
            }
        }, 150);
    });

    document.addEventListener('click', (event) => {
        if (!event.target.closest(`#${AUTOFILL_POPUP_ID}, #${GENERATOR_BTN_ID}`)) {
            removeAutofillPopup();
        }
    });
    
    document.addEventListener('submit', handleFormSubmit, true);
    
    // 8. Expose function to be called from Python
    window.wemphixFillPassword = function(password) {
        if (activePasswordField) {
            activePasswordField.value = password;
            activePasswordField.dispatchEvent(new Event('input', { bubbles: true }));
        }
    };

    // 9. Initial setup
    injectStyles();
})();

