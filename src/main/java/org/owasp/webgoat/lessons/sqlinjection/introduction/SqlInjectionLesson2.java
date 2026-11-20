/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Set;
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
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private static final String EMPLOYEE_QUERY =
      "SELECT * FROM employees WHERE first_name = ? AND last_name = ?";

  private static final String DISPLAY_QUERY =
      "SELECT * FROM employees WHERE first_name = 'Bob' AND last_name = 'Franco'";

  private static final Set<String> SUPPORTED_QUERIES =
      Set.of(
          "select*fromemployeeswherefirst_name='bob'andlast_name='franco'",
          "select*fromemployeeswherelast_name='franco'andfirst_name='bob'",
          "select*fromemployeeswherelast_name='franco'",
          "select*fromemployeeswherefirst_name='bob'",
          "selectdepartmentfromemployeeswherefirst_name='bob'andlast_name='franco'",
          "selectdepartmentfromemployeeswherelast_name='franco'andfirst_name='bob'",
          "selectdepartmentfromemployeeswherelast_name='franco'",
          "selectdepartmentfromemployeeswherefirst_name='bob'");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (!isSupportedQuery(query)) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }

    try (var connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                EMPLOYEE_QUERY, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      statement.setString(1, "Bob");
      statement.setString(2, "Franco");
      ResultSet results = statement.executeQuery();
      StringBuilder output = new StringBuilder();

      if (!results.first()) {
        return failed(this).feedback("sql-injection.2.failed").build();
      }

      if ("Marketing".equals(results.getString("department"))) {
        output
            .append("<span class='feedback-positive'>")
            .append(DISPLAY_QUERY)
            .append("</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      } else {
        return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }

  private static boolean isSupportedQuery(String query) {
    if (query == null) {
      return false;
    }
    String normalized =
        query.replaceAll("\\s+", "").replaceAll(";+$", "").toLowerCase(Locale.ROOT);
    return SUPPORTED_QUERIES.contains(normalized);
  }
}
