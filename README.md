# SQL-RBAC-XSS-Capstone-project
Creation of a Capstone project with SQL, RBAC and Xss files. 
Identified vulnerabilities:

SQL Injection risk: If user input is directly concatenated into SQL queries, an attacker can bypass authentication or modify data.

XSS risk: If user comments containing HTML/JavaScript are displayed without escaping, they can execute in a browser.

Fixes applied:

SQL Injection prevention:

All database queries use prepared statements (sqlite3_prepare_v2, sqlite3_bind_text) instead of string concatenation.

Authentication checks bind username and password as parameters, so malicious input like admin' OR '1'='1 does not change the query logic.

XSS mitigation:

User comments are stored as plain text.

Before displaying, comments are passed through html_escape, which replaces <, >, &, ", ' with safe HTML entities.

This prevents scripts from being interpreted as HTML/JS.


How Copilot Helped Create This Project
Copilot played a central role throughout the development of this security‑focused C project. Its contributions covered code generation, debugging, secure‑coding guidance, and test creation. Below is a structured summary aligned with the project requirements.

1. Secure Code Generation (Input Validation & SQL Injection Prevention)
Copilot assisted in generating safe patterns for handling user input in C, including:

Bounds‑checked input reading using fgets

Validation functions ensuring non‑empty, size‑limited input

Secure SQL queries using prepared statements instead of unsafe string concatenation

Copilot suggested the correct usage of sqlite3_prepare_v2, sqlite3_bind_text, and sqlite3_step, ensuring that authentication queries were fully protected against SQL injection.

2. Authentication & Authorization (RBAC)
Copilot helped design the structure of the authentication system:

A User struct containing id, username, and role

A secure login function using prepared statements

A role‑based access control check (has_admin_access)

Copilot also generated safe patterns for comparing roles and preventing privilege escalation.

3. Debugging & Fixing Security Vulnerabilities (SQLi & XSS)
During development, Copilot identified several potential vulnerabilities:

SQL Injection risks in early versions of the login query

XSS risks when displaying user comments

Copilot proposed fixes such as:

Replacing raw SQL strings with prepared statements

Adding an html_escape function to sanitize user‑generated content

Improving error handling and input validation

These suggestions directly eliminated exploitable weaknesses.

4. Generating and Running Security Tests
Copilot generated the initial structure for the test suite, including:

A SQL injection test attempting to bypass authentication

An XSS test verifying that HTML/JS payloads are escaped

A simple test runner printing PASS/FAIL results

Copilot also helped refine the tests to ensure they covered realistic attack scenarios.

5. Summary and Documentation Support
Copilot assisted in writing:

The vulnerability summary

Explanations of the fixes

Comments inside the C source code

The Makefile

The overall project structure

This ensured the documentation was clear, complete, and aligned with the project rubric.

Input validation:

validate_input ensures inputs are non-empty and within a reasonable length, reducing the risk of buffer overflows and malformed data.
