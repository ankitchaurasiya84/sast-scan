const scanCode = (code) => {
  let data = [];
  const vulnerabilities = [
    {
      pattern: /eval\s*\(/,
      message: "Use of eval() - allows execution of arbitrary code",
      fix: "Avoid using eval(). Use JSON.parse() for JSON strings.",
    },
    {
      pattern: /SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*['"`]/,
      message: "SQL Injection - unsafe string concatenation in queries",
      fix: "Use parameterized queries or prepared statements.",
    },
    {
      pattern: /crypto\.createHash\s*\(\s*['"`]md5['"`]\s*\)/,
      message: "Insecure hashing function (MD5)",
      fix: "Use a stronger hashing function like bcrypt or Argon2.",
    },
    {
      pattern:
        /document\.getElementById\s*\(\s*['"`]content['"`]\s*\)\s*\.innerHTML\s*=/,
      message:
        "XSS (Cross-Site Scripting) - Outputting raw user input into the DOM",
      fix: "Sanitize user inputs before using them in innerHTML.",
    },
    {
      pattern: /console\.log\s*input/,
      message: "No input validation - potential unsafe characters or overflows",
      fix: "Validate and sanitize user inputs.",
    },
    {
      pattern:
        /const\s+(password|pass|pwd|secret|apikey|key)\s*=\s*['"`][^'"]+['"`]/i,
      message: "Hardcoded credentials - storing sensitive info in code",
      fix: "Store sensitive information in environment variables.",
    },
    {
      pattern: /^(a+)+$/,
      message: "Weak regex - Inefficient leading to ReDoS",
      fix: "Optimize the regular expression or use a different approach.",
    },
    {
      pattern: /Object\.assign\s*\(target,\s*source\)/,
      message: "Prototype Pollution - Object may get polluted",
      fix: "Use a library like lodash's merge for deep cloning.",
    },
    {
      pattern: /alert\s*\(/,
      message:
        "Use of alert() - can be abused for social engineering or disruption",
      fix: "Use console.log or UI notifications instead.",
    },
    {
      pattern: /fs\.readFileSync\s*\(filePath,\s*['"`]utf8['"`]\s*\)/,
      message: "Lack of proper error handling - can leak sensitive information",
      fix: "Implement proper error handling and avoid leaking error messages.",
    },
    {
      pattern: /const\s+url\s*=\s*['"`]http:\/\//,
      message:
        "Missing HTTPS - unencrypted sensitive information sent over HTTP",
      fix: "Use HTTPS URLs for secure communication.",
    },
    {
      pattern: /setInterval\s*\(\s*\(\)\s*=>\s*{.*data.push/,
      message: "Memory leak - Unbounded growth of data array",
      fix: "Clear the interval after a certain condition or limit the growth of the array.",
    },
    {
      pattern: /path\.join\s*\(['"`]\/home\/user\/data['"`],\s*input\)/,
      message: "Unescaped file paths - path traversal attack",
      fix: "Validate and sanitize file paths to prevent path traversal.",
    },
    {
      pattern: /\.innerHTML\s*=\s*input/,
      message:
        "Directly assigning untrusted input to innerHTML - XSS vulnerability",
      fix: "Use textContent or sanitize input before assignment.",
    },
    {
      pattern: /new\s+Function\(['"`].*['"`]\)/,
      message:
        "Dynamic code execution - potential for arbitrary code execution",
      fix: "Avoid using new Function().",
    },
    {
      pattern: /async\s+function\s+\w+\s*\(\)\s*{.*await\s+fetch\(/,
      message:
        "No timeout for network requests - could lead to hanging requests",
      fix: "Add timeout handling for fetch requests.",
    },
    {
      pattern: /window\.location\.hash\s*=\s*['"`].*['"`]/,
      message: "Open Redirect - may lead to phishing attacks",
      fix: "Validate and sanitize URLs before assigning to window.location.",
    },
    {
      pattern: /res\.send\s*\(err\s*message\s*\)/,
      message: "Error message exposure - might leak sensitive information",
      fix: "Log errors internally and send generic messages to clients.",
    },
    {
      pattern: /res\.json\s*\({.*password.*}\)/,
      message: "Exposing sensitive information in API responses",
      fix: "Avoid including sensitive data like passwords in API responses.",
    },
    {
      pattern: /new\s+Buffer\s*\(/,
      message: "Deprecated Buffer constructor - can be unsafe",
      fix: "Use Buffer.from() instead for safer buffer handling.",
    },
    {
      pattern: /innerHTML\s*=\s*document\.cookie/,
      message: "DOM-based XSS - writing cookies to innerHTML",
      fix: "Avoid using cookies in the DOM or sanitize them.",
    },
    {
      pattern: /child_process\.exec\s*\(.*\)/,
      message: "Command Injection - executing untrusted commands",
      fix: "Use execFile or spawn with input validation.",
    },
    {
      pattern: /require\s*\(\s*['"`]dotenv['"`]\s*\)\s*\.config\(\s*\)/,
      message: "Potential unconfigured environment loading",
      fix: "Ensure environment variables are validated and configured securely.",
    },
    {
      pattern:
        /localStorage\.setItem\s*\(\s*['"`].*['"`]\s*,\s*['"`].*['"`]\s*\)/,
      message:
        "Storing sensitive data in localStorage - can be accessed via XSS",
      fix: "Avoid storing sensitive data in localStorage. Use secure cookies or server-side storage.",
    },
    {
      pattern:
        /sessionStorage\.setItem\s*\(\s*['"`].*['"`]\s*,\s*['"`].*['"`]\s*\)/,
      message:
        "Storing sensitive data in sessionStorage - can be accessed via XSS",
      fix: "Avoid storing sensitive data in sessionStorage. Use secure cookies or server-side storage.",
    },
    {
      pattern:
        /JSON\.parse\s*\(\s*localStorage\.getItem\s*\(\s*['"`].*['"`]\s*\)\s*\)/,
      message:
        "Parsing untrusted data from localStorage - potential for JSON injection",
      fix: "Validate and sanitize data before parsing.",
    },
    {
      pattern: /XMLHttpRequest\s*\(\s*\)/,
      message:
        "Using XMLHttpRequest - potential for CSRF and other vulnerabilities",
      fix: "Use fetch API with appropriate security headers and CORS settings.",
    },
    {
      pattern: /<script\s+.*src\s*=\s*['"`].*['"`]\s*><\/script>/,
      message: "Including external scripts - potential for XSS",
      fix: "Use Content Security Policy (CSP) to restrict script sources.",
    },
    {
      pattern: /<iframe\s+.*src\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Including external iframes - potential for clickjacking",
      fix: "Use X-Frame-Options header to prevent clickjacking.",
    },
    {
      pattern: /<form\s+.*action\s*=\s*['"`].*['"`]\s*><\/form>/,
      message: "Unvalidated form action - potential for CSRF",
      fix: "Use CSRF tokens and validate form actions.",
    },
    {
      pattern: /<input\s+.*type\s*=\s*['"`]password['"`]\s*><\/input>/,
      message:
        'Password input without autocomplete="off" - potential for browser autofill vulnerabilities',
      fix: 'Add autocomplete="off" to password inputs.',
    },
    {
      pattern: /<a\s+.*href\s*=\s*['"`]javascript:.*['"`]\s*><\/a>/,
      message: "JavaScript in href attribute - potential for XSS",
      fix: "Avoid using JavaScript in href attributes. Use event listeners instead.",
    },
    {
      pattern:
        /<img\s+.*src\s*=\s*['"`].*['"`]\s+onerror\s*=\s*['"`].*['"`]\s*><\/img>/,
      message: "onerror attribute in img tag - potential for XSS",
      fix: "Avoid using onerror attributes. Use event listeners instead.",
    },
    {
      pattern: /<div\s+.*onclick\s*=\s*['"`].*['"`]\s*><\/div>/,
      message: "Inline event handlers - potential for XSS",
      fix: "Avoid using inline event handlers. Use event listeners instead.",
    },
    {
      pattern: /<style\s+.*>.*<\/style>/,
      message: "Inline styles - potential for CSS injection",
      fix: "Avoid using inline styles. Use external stylesheets.",
    },
    {
      pattern: /<link\s+.*href\s*=\s*['"`].*['"`]\s*><\/link>/,
      message: "Including external stylesheets - potential for CSS injection",
      fix: "Use Content Security Policy (CSP) to restrict stylesheet sources.",
    },
    {
      pattern: /<meta\s+.*http-equiv\s*=\s*['"`]refresh['"`]\s*><\/meta>/,
      message: "Meta refresh - potential for phishing",
      fix: "Avoid using meta refresh. Use JavaScript for redirects if necessary.",
    },
    {
      pattern: /<object\s+.*data\s*=\s*['"`].*['"`]\s*><\/object>/,
      message: "Including external objects - potential for XSS",
      fix: "Avoid using external objects. Use safer alternatives.",
    },
    {
      pattern: /<embed\s+.*src\s*=\s*['"`].*['"`]\s*><\/embed>/,
      message: "Including external embeds - potential for XSS",
      fix: "Avoid using external embeds. Use safer alternatives.",
    },
    {
      pattern: /<video\s+.*src\s*=\s*['"`].*['"`]\s*><\/video>/,
      message: "Including external videos - potential for XSS",
      fix: "Avoid using external videos. Use safer alternatives.",
    },
    {
      pattern: /<audio\s+.*src\s*=\s*['"`].*['"`]\s*><\/audio>/,
      message: "Including external audio - potential for XSS",
      fix: "Avoid using external audio. Use safer alternatives.",
    },
    {
      pattern: /<source\s+.*src\s*=\s*['"`].*['"`]\s*><\/source>/,
      message: "Including external sources - potential for XSS",
      fix: "Avoid using external sources. Use safer alternatives.",
    },
    {
      pattern: /<track\s+.*src\s*=\s*['"`].*['"`]\s*><\/track>/,
      message: "Including external tracks - potential for XSS",
      fix: "Avoid using external tracks. Use safer alternatives.",
    },
    {
      pattern: /<canvas\s+.*><\/canvas>/,
      message: "Using canvas - potential for XSS",
      fix: "Avoid using canvas for sensitive operations. Use safer alternatives.",
    },
    {
      pattern: /<svg\s+.*><\/svg>/,
      message: "Using SVG - potential for XSS",
      fix: "Avoid using inline SVG. Use external SVG files with proper sanitization.",
    },
    {
      pattern: /<math\s+.*><\/math>/,
      message: "Using MathML - potential for XSS",
      fix: "Avoid using inline MathML. Use external MathML files with proper sanitization.",
    },
    {
      pattern: /<iframe\s+.*sandbox\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe sandbox - potential for XSS",
      fix: "Avoid using iframe sandbox. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*srcdoc\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe srcdoc - potential for XSS",
      fix: "Avoid using iframe srcdoc. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allow\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allow - potential for XSS",
      fix: "Avoid using iframe allow. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpointerlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpointerlock - potential for XSS",
      fix: "Avoid using iframe allowpointerlock. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpresentation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpresentation - potential for XSS",
      fix: "Avoid using iframe allowpresentation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowscripts\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowscripts - potential for XSS",
      fix: "Avoid using iframe allowscripts. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowtopnavigation\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtopnavigation - potential for XSS",
      fix: "Avoid using iframe allowtopnavigation. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowtransparency\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowtransparency - potential for XSS",
      fix: "Avoid using iframe allowtransparency. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowforms\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowforms - potential for XSS",
      fix: "Avoid using iframe allowforms. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowfullscreen\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowfullscreen - potential for XSS",
      fix: "Avoid using iframe allowfullscreen. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*allowpaymentrequest\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpaymentrequest - potential for XSS",
      fix: "Avoid using iframe allowpaymentrequest. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowusermedia\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowusermedia - potential for XSS",
      fix: "Avoid using iframe allowusermedia. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowvr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowvr - potential for XSS",
      fix: "Avoid using iframe allowvr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowwebgl\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowwebgl - potential for XSS",
      fix: "Avoid using iframe allowwebgl. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowxr\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowxr - potential for XSS",
      fix: "Avoid using iframe allowxr. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowpopups\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowpopups - potential for XSS",
      fix: "Avoid using iframe allowpopups. Use safer alternatives.",
    },
    {
      pattern: /<iframe\s+.*allowmodals\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe allowmodals - potential for XSS",
      fix: "Avoid using iframe allowmodals. Use safer alternatives.",
    },
    {
      pattern:
        /<iframe\s+.*alloworientationlock\s*=\s*['"`].*['"`]\s*><\/iframe>/,
      message: "Using iframe alloworientationlock - potential for XSS",
      fix: "Avoid using iframe alloworientationlock. Use safer alternatives.",
    },
  ];

  const lines = code.split("\n");
  const outputSet = new Set();

  lines.forEach((line, lineNumber) => {
    vulnerabilities.forEach((vulnerability) => {
      if (vulnerability.pattern.test(line)) {
        const message = {
          message: `Vulnerability: ${vulnerability.message}`,
          fix: `Recommendation: ${vulnerability.fix}`,
          lineNumber: `Vulnerable Code Line (${
            lineNumber + 1
          }): ${line.trim()}`,
        };

        outputSet.add(JSON.stringify(message));
      }
    });
  });

  const uniqueOutputArray = Array.from(outputSet).map((item) =>
    JSON.parse(item)
  );

  if (uniqueOutputArray.length === 0) {
    return [{ message: "No vulnerabilities found." }];
  } else {
    return uniqueOutputArray;
  }
};

export default scanCode;
