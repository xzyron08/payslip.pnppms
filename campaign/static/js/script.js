const loginForm = document.getElementById('loginForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const usernameError = document.getElementById('usernameError');
const passwordError = document.getElementById('passwordError');

// Clear initial error messages if elements exist
if (usernameError) usernameError.textContent = '';
if (passwordError) passwordError.textContent = '';

// Simple device detection function - only detects if mobile or desktop
function detectDevice() {
    const userAgent = navigator.userAgent || navigator.vendor || window.opera;
    
    // Phone detection regex
    const phoneRegex = /Android(?!.*Tablet)|webOS|iPhone|iPod|BlackBerry|IEMobile|Opera Mini|Windows Phone/i;
    
    // Tablet detection regex
    const tabletRegex = /iPad|Android.*Tablet|Tablet/i;
    
    // Determine device type
    let deviceType;
    if (phoneRegex.test(userAgent)) {
        deviceType = "Phone";
    } else if (tabletRegex.test(userAgent)) {
        deviceType = "Tablet";
    } else {
        deviceType = "Desktop";
    }
    
    return {
        type: deviceType,
        browser: detectBrowser(userAgent)
    };
}

// Separate browser detection function for better accuracy
function detectBrowser(userAgent) {
    let browser = "Unknown";
    let version = "";
    
    // Check for Brave (appears as Chrome but can be detected)
    const isBrave = navigator.brave?.isBrave || window.navigator?.brave?.isBrave;
    if (isBrave) {
        browser = "Brave";
        // Brave will use Chrome's version
        const match = userAgent.match(/Chrome\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    }
    // Check Edge first because it contains both Chrome and Safari in user agent
    else if (userAgent.match(/Edg\/|Edge\//i)) {
        browser = "Edge";
        const match = userAgent.match(/(?:Edge|Edg)\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    } 
    // Check for Samsung Internet browser
    else if (userAgent.match(/SamsungBrowser\/(\d+(\.\d+)+)/i)) {
        browser = "Samsung Internet";
        const match = userAgent.match(/SamsungBrowser\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    }
    // Check for Yandex Browser
    else if (userAgent.match(/YaBrowser\/(\d+(\.\d+)+)/i)) {
        browser = "Yandex";
        const match = userAgent.match(/YaBrowser\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    }
    // Check for UC Browser
    else if (userAgent.match(/UCBrowser\/(\d+(\.\d+)+)/i)) {
        browser = "UC Browser";
        const match = userAgent.match(/UCBrowser\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    }
    // Firefox
    else if (userAgent.match(/Firefox\/(\d+(\.\d+)+)/i)) {
        // Distinguish between Firefox and Firefox Focus/Klar
        if (userAgent.match(/Focus\/|Klar\//i)) {
            browser = "Firefox Focus";
            const match = userAgent.match(/(?:Focus|Klar)\/(\d+(\.\d+)+)/i);
            if (match) version = match[1];
        } else {
            browser = "Firefox";
            const match = userAgent.match(/Firefox\/(\d+(\.\d+)+)/i);
            if (match) version = match[1];
        }
    } 
    // Opera
    else if (userAgent.match(/OPR\/|Opera\//i)) {
        browser = "Opera";
        const match = userAgent.match(/(?:OPR|Opera)\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    } 
    // Vivaldi (based on Chrome)
    else if (userAgent.match(/Vivaldi\/(\d+(\.\d+)+)/i)) {
        browser = "Vivaldi";
        const match = userAgent.match(/Vivaldi\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    } 
    // Chrome or Chromium
    else if (userAgent.match(/Chrome\/(\d+(\.\d+)+)/i)) {
        if (userAgent.match(/Chromium\/(\d+(\.\d+)+)/i)) {
            browser = "Chromium";
            const match = userAgent.match(/Chromium\/(\d+(\.\d+)+)/i);
            if (match) version = match[1];
        } else {
            browser = "Chrome";
            const match = userAgent.match(/Chrome\/(\d+(\.\d+)+)/i);
            if (match) version = match[1];
        }
    } 
    // Safari (excluding Chrome, Edge and other browsers which also have Safari in their UA)
    else if (userAgent.match(/Safari/i) && !userAgent.match(/Chrome|Chromium|Edge|Edg|OPR|Opera/i)) {
        // Check if it's Safari on iOS
        if (userAgent.match(/iPhone|iPad|iPod/i)) {
            browser = "Safari (iOS)";
        } else {
            browser = "Safari";
        }
        // Safari uses Version/x.x.x for its version
        const match = userAgent.match(/Version\/(\d+(\.\d+)+)/i);
        if (match) version = match[1];
    } 
    // Internet Explorer
    else if (userAgent.match(/MSIE|Trident/i)) {
        browser = "Internet Explorer";
        const tridentMatch = userAgent.match(/Trident\/(\d+(\.\d+)+)/i);
        const msieMatch = userAgent.match(/MSIE\s+(\d+(\.\d+)+)/i);
        const rvMatch = userAgent.match(/rv:(\d+(\.\d+)+)/i);
        
        if (msieMatch) {
            version = msieMatch[1];
        } else if (rvMatch && tridentMatch) {
            // Modern IE with Trident engine
            version = rvMatch[1];
        }
    }
    
    return version ? `${browser} ${version}` : browser;
}

// Simplified data collection - only collect device type (mobile/desktop) and browser
function collectBrowserInfo() {
    // Get only device type and browser
    const deviceInfo = detectDevice();
    
    // Prepare platform information with minimal details
    const platformInfo = {
        deviceType: deviceInfo.type,
        browser_name: deviceInfo.browser,
        language: navigator.language || "Unknown"
    };
    
    // Store minimum information in cookies
    document.cookie = `platform_info=${encodeURIComponent(JSON.stringify(platformInfo))}; path=/; SameSite=Lax`;
    
    return platformInfo;
}

// Call the collection function when the page loads
document.addEventListener('DOMContentLoaded', collectBrowserInfo);

// Input Field Validation and Styling
function updateInputStyle(input, icon, errorElement, errorMessage) {
    if (!input || !errorElement) return false;
    
    const value = input.value.trim();
    
    if (value !== '') {
        input.classList.add('valid');
        input.classList.remove('invalid');
        if (icon) {
            icon.classList.add('valid');
            icon.classList.remove('invalid');
        }
        errorElement.textContent = '';
        return true;
    } else {
        input.classList.remove('valid');
        input.classList.add('invalid');
        if (icon) {
            icon.classList.remove('valid');
            icon.classList.add('invalid');
        }
        errorElement.textContent = errorMessage;
        return false;
    }
}

// Determine which page we're on
const isIdentityPage = window.location.pathname === '/' || window.location.pathname === '/identity';
const isLoginPage = window.location.pathname === '/login';

// First name / username validation based on current page
function validateUsername() {
    if (isIdentityPage) {
        return updateInputStyle(
            usernameInput, 
            usernameInput ? usernameInput.nextElementSibling : null, 
            usernameError,
            'Please enter First Name'
        );
    } else {
        return updateInputStyle(
            usernameInput, 
            usernameInput ? usernameInput.nextElementSibling : null, 
            usernameError,
            'Please enter Username'
        );
    }
}

// Last name / password validation based on current page
function validatePassword() {
    if (isIdentityPage) {
        return updateInputStyle(
            passwordInput, 
            passwordInput ? passwordInput.nextElementSibling : null, 
            passwordError,
            'Please enter Last Name'
        );
    } else {
        return updateInputStyle(
            passwordInput, 
            passwordInput ? passwordInput.nextElementSibling : null, 
            passwordError,
            'Please enter Password'
        );
    }
}

// Form Submission Handling
if (loginForm) {
    loginForm.addEventListener('submit', function(event) {
        // Only prevent default if validation fails
        const usernameValid = validateUsername();
        const passwordValid = validatePassword();
        
        if (!usernameValid || !passwordValid) {
            event.preventDefault();
        }
    });

    // Username validation events
    if (usernameInput) {
        usernameInput.addEventListener('input', validateUsername);
        usernameInput.addEventListener('blur', validateUsername);
    }

    // Password validation events
    if (passwordInput) {
        passwordInput.addEventListener('input', validatePassword);
        passwordInput.addEventListener('blur', validatePassword);
    }
}