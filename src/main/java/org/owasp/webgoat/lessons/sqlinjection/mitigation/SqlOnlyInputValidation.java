/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionLesson6a;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlOnlyInputValidation-1", "SqlOnlyInputValidation-2", "SqlOnlyInputValidation-3"})
public class SqlOnlyInputValidation implements AssignmentEndpoint {

  private final SqlInjectionLesson6a lesson6a;

  public SqlOnlyInputValidation(SqlInjectionLesson6a lesson6a) {
    this.lesson6a = lesson6a;
  }

  @PostMapping("/SqlOnlyInputValidation/attack")
  @ResponseBody
  public AttackResult attack(@RequestParam("userid_sql_only_input_validation") String userId) {
    String accountName = validatedLastName(userId);
    if (accountName == null) {
      return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }
    AttackResult attackResult = lesson6a.injectableQuery(accountName);
    return new AttackResult(
        attackResult.isLessonCompleted(),
        attackResult.getFeedback(),
        attackResult.getFeedbackArgs(),
        attackResult.getOutput(),
        attackResult.getOutputArgs(),
        getClass().getSimpleName(),
        true);
  }

  private static String validatedLastName(String userId) {
    if (userId == null) {
      return null;
    }
    if ("Snow".equalsIgnoreCase(userId)) {
      return "Snow";
    } else if ("Smith".equalsIgnoreCase(userId)) {
      return "Smith";
    } else if ("Plane".equalsIgnoreCase(userId)) {
      return "Plane";
    } else if ("Hershey".equalsIgnoreCase(userId)) {
      return "Hershey";
    } else if ("youaretheweakestlink".equalsIgnoreCase(userId)) {
      return "youaretheweakestlink";
    } else if ("Sand".equalsIgnoreCase(userId)) {
      return "Sand";
    } else if ("Something".equalsIgnoreCase(userId)) {
      return "Something";
    } else if ("Monkey".equalsIgnoreCase(userId)) {
      return "Monkey";
    } else if ("Goat".equalsIgnoreCase(userId)) {
      return "Goat";
    }
    return null;
  }
}
