/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  private static final String ADD_PHONE_COLUMN =
      "ALTER TABLE employees ADD phone varchar(20)";

  private static final Pattern ALLOWED_QUERY =
      Pattern.compile(
          "^ALTER TABLE EMPLOYEES ADD (COLUMN )?PHONE"
              + "( VARCHAR|VARCHAR2|NVARCHAR|NVARCHAR2|CHAR|CHARACTER|NCHAR|TEXT|CLOB"
              + "|INT|INTEGER|BIGINT|SMALLINT|TINYINT|NUMERIC|DECIMAL|NUMBER"
              + "|FLOAT|DOUBLE|REAL|BOOLEAN|DATE|TIME|TIMESTAMP|BINARY|VARBINARY|BLOB)"
              + "( ?[(][0-9]+(, ?[0-9]+)?[)])?$");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (!isAllowedQuery(query)) {
      return failed(this).build();
    }
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        statement.executeUpdate(ADD_PHONE_COLUMN);
        connection.commit();
        ResultSet results = statement.executeQuery("SELECT phone from employees;");
        StringBuilder output = new StringBuilder();
        // user completes lesson if column phone exists
        if (results.first()) {
          output.append("<span class='feedback-positive'>" + query + "</span>");
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }

  private static boolean isAllowedQuery(String query) {
    if (query == null) {
      return false;
    }
    String normalized = query.trim().toUpperCase(Locale.ROOT).replaceAll("\\s+", " ");
    if (normalized.endsWith(";")) {
      normalized = normalized.substring(0, normalized.length() - 1).trim();
    }
    return ALLOWED_QUERY.matcher(normalized).matches();
  }
}
