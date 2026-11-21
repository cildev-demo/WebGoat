/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
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
import java.util.Set;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final String UPDATE_BARNETT_DEPARTMENT =
      "UPDATE employees SET department = 'Sales' WHERE first_name = 'Tobi'"
          + " AND last_name = 'Barnett'";

  private static final String CHECK_BARNETT_DEPARTMENT =
      "SELECT * FROM employees WHERE last_name = 'Barnett'";

  private static final String DISPLAY_QUERY =
      "UPDATE employees SET department = 'Sales' WHERE first_name = 'Tobi'"
          + " AND last_name = 'Barnett'";

  private static final Set<String> SUPPORTED_QUERIES =
      Set.of(
          "updateemployeessetdepartment='sales'wherefirst_name='tobi'andlast_name='barnett'",
          "updateemployeessetdepartment='sales'wherelast_name='barnett'andfirst_name='tobi'",
          "updateemployeessetdepartment='sales'wherelast_name='barnett'",
          "updateemployeessetdepartment='sales'wherefirst_name='tobi'",
          "updateemployeessetdepartment='sales'whereuserid='89762'",
          "updateemployeessetdepartment='sales'whereuserid=89762");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (!isSupportedQuery(query)) {
      return failed(this).build();
    }
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
              connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
          Statement checkStatement =
              connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        statement.executeUpdate(UPDATE_BARNETT_DEPARTMENT);
        ResultSet results = checkStatement.executeQuery(CHECK_BARNETT_DEPARTMENT);
        StringBuilder output = new StringBuilder();
        // user completes lesson if the department of Tobi Barnett now is 'Sales'
        results.first();
        if ("Sales".equals(results.getString("department"))) {
          output.append("<span class='feedback-positive'>");
          output.append(DISPLAY_QUERY);
          output.append("</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(HtmlUtils.htmlEscape(sqle.getMessage())).build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(HtmlUtils.htmlEscape(this.getClass().getName() + " : " + e.getMessage()))
          .build();
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
