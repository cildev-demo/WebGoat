/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    // HSQLDB does not support CREATE USER with IF NOT EXISTS so we need to do it in code (using
    // DROP first will throw error if user does not exists)
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    createUser();
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    String normalizedQuery = normalize(query);
    if (!isAllowedGrant(normalizedQuery)) {
      return failed(this).output("Your query was: " + HtmlUtils.htmlEscape(query)).build();
    }
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(
              ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
        if (isGrantAll(normalizedQuery)) {
          statement.execute("GRANT ALL ON grant_rights TO unauthorized_user");
        } else if (isGrantAllPrivileges(normalizedQuery)) {
          statement.execute("GRANT ALL PRIVILEGES ON grant_rights TO unauthorized_user");
        } else {
          statement.execute("GRANT SELECT ON grant_rights TO unauthorized_user");
        }
        if (checkSolution(connection)) {
          return success(this).build();
        }
        return failed(this).output("Your query was: " + HtmlUtils.htmlEscape(query)).build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName()
                  + " : "
                  + HtmlUtils.htmlEscape(e.getMessage())
                  + "<br> Your query was: "
                  + HtmlUtils.htmlEscape(query))
          .build();
    }
  }

  private static String normalize(String query) {
    if (query == null) {
      return "";
    }
    String normalized = query.trim();
    while (normalized.endsWith(";")) {
      normalized = normalized.substring(0, normalized.length() - 1).trim();
    }
    return normalized;
  }

  private static boolean isAllowedGrant(String query) {
    return isGrantSelect(query) || isGrantAll(query) || isGrantAllPrivileges(query);
  }

  private static boolean isGrantSelect(String query) {
    return "GRANT SELECT ON grant_rights TO unauthorized_user".equalsIgnoreCase(query);
  }

  private static boolean isGrantAll(String query) {
    return "GRANT ALL ON grant_rights TO unauthorized_user".equalsIgnoreCase(query);
  }

  private static boolean isGrantAllPrivileges(String query) {
    return "GRANT ALL PRIVILEGES ON grant_rights TO unauthorized_user".equalsIgnoreCase(query);
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}
