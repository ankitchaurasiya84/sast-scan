const scanCode = (code) => {
    let data = [];
    const vulnerabilities = [
        { pattern: /eval\s*\(/, message: 'Use of eval() - allows execution of arbitrary code', fix: 'Avoid using eval(). Use JSON.parse() for JSON strings.' },
        { pattern: /SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*['"`]/, message: 'SQL Injection - unsafe string concatenation in queries', fix: 'Use parameterized queries or prepared statements.' },
        { pattern: /crypto\.createHash\s*\(\s*['"`]md5['"`]\s*\)/, message: 'Insecure hashing function (MD5)', fix: 'Use a stronger hashing function like bcrypt or Argon2.' },
        { pattern: /document\.getElementById\s*\(\s*['"`]content['"`]\s*\)\s*\.innerHTML\s*=/, message: 'XSS (Cross-Site Scripting) - Outputting raw user input into the DOM', fix: 'Sanitize user inputs before using them in innerHTML.' },
        { pattern: /console\.log\s*$begin:math:text$\\s*input\\s*$end:math:text$/, message: 'No input validation - potential unsafe characters or overflows', fix: 'Validate and sanitize user inputs.' },
        { pattern: /const\s+(password|pass|pwd|secret|apikey|key)\s*=\s*['"`][^'"]+['"`]/i, message: 'Hardcoded credentials - storing sensitive info in code', fix: 'Store sensitive information in environment variables.' },
        { pattern: /^(a+)+$/, message: 'Weak regex - Inefficient leading to ReDoS', fix: 'Optimize the regular expression or use a different approach.' },
        { pattern: /Object\.assign\s*$begin:math:text$\\s*target\\s*,\\s*source\\s*$end:math:text$/, message: 'Prototype Pollution - Object may get polluted', fix: 'Use a library like lodash\'s merge for deep cloning.' },
        { pattern: /alert\s*$begin:math:text$/, message: 'Use of alert() - can be abused for social engineering or disruption', fix: 'Use console.log or UI notifications instead.' },
        { pattern: /fs\.readFileSync\s*\(\s*filePath\s*,\s*['"`]utf8['"`]\s*\)/, message: 'Lack of proper error handling - can leak sensitive information', fix: 'Implement proper error handling and avoid leaking error messages.' },
        { pattern: /const\s+url\s*=\s*['"`]http:\/\//, message: 'Missing HTTPS - unencrypted sensitive information sent over HTTP', fix: 'Use HTTPS URLs for secure communication.' },
        { pattern: /setInterval\s*\(\s*\(\)\s*=>\s*{.*data.push/, message: 'Memory leak - Unbounded growth of data array', fix: 'Clear the interval after a certain condition or limit the growth of the array.' },
        { pattern: /path\.join\s*\(\s*['"`]\/home\/user\/data['"`]\s*,\s*input\s*\)/, message: 'Unescaped file paths - path traversal attack', fix: 'Validate and sanitize file paths to prevent path traversal.' },
    ];

    
    const lines = code.split('\n');
    const outputSet = new Set();


    lines.forEach((line, lineNumber) => {
        vulnerabilities.forEach(vulnerability => {
            if (vulnerability.pattern.test(line)) {
               
                const message = {
                    message: `Vulnerability: ${vulnerability.message}`,
                    fix: `Recommendation: ${vulnerability.fix}`,
                    lineNumber: `Vulnerable Code Line (${lineNumber + 1}): ${line.trim()}`,
                };
               
                outputSet.add(JSON.stringify(message)); 
            }
        });
    });

   
    const uniqueOutputArray = Array.from(outputSet).map(item => JSON.parse(item));

   
    if (uniqueOutputArray.length === 0) {
        return [{ message: 'No vulnerabilities found.' }];
    } else {
        return uniqueOutputArray;
    }
};

export default scanCode;