# SQL Injection in MCP Servers

## Overview

SQL injection vulnerabilities in MCP servers occur when user input is directly concatenated into SQL queries without proper sanitization or parameterization.

## Common Scenarios

### Direct Query Construction
```sql
-- Vulnerable example
query = "SELECT * FROM users WHERE id = " + user_input
```

### LLM-Generated Queries
MCP servers that use LLMs to generate SQL queries are particularly vulnerable:
- LLMs may generate unsafe SQL based on user prompts
- Context poisoning can influence query generation
- No validation of LLM-generated queries

## Exploitation Techniques

### Basic Injection
```
'; DROP TABLE users; --
```

### Information Disclosure
```
' UNION SELECT username, password FROM admin_users --
```

### Blind SQL Injection
```
' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --
```

## Mitigation Strategies

1. **Use Parameterized Queries**
   ```python
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   ```

2. **Input Validation**
   - Whitelist allowed characters
   - Validate data types
   - Implement length limits

3. **LLM Query Validation**
   - Parse and validate LLM-generated SQL
   - Use SQL query allow-lists
   - Implement query complexity limits

4. **Principle of Least Privilege**
   - Use dedicated database users with minimal permissions
   - Restrict access to sensitive tables
   - Implement database-level access controls

## Testing for SQL Injection

Use automated scanners and manual testing:
- SQLMap for automated detection
- Manual payload injection
- Code review of query construction

## References

- [OWASP SQL Injection Prevention](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection)
- [CWE-89: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/89.html)