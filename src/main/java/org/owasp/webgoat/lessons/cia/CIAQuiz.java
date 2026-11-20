/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cia;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CIAQuiz implements AssignmentEndpoint {

  private final String[] solutions = {"Solution 3", "Solution 1", "Solution 4", "Solution 2"};
  private final Map<String, boolean[]> guesses = new ConcurrentHashMap<>();

  @PostMapping("/cia/quiz")
  @ResponseBody
  public AttackResult completed(
      @CurrentUsername String username,
      @RequestParam String[] question_0_solution,
      @RequestParam String[] question_1_solution,
      @RequestParam String[] question_2_solution,
      @RequestParam String[] question_3_solution) {
    int correctAnswers = 0;

    String[] givenAnswers = {
      question_0_solution[0], question_1_solution[0], question_2_solution[0], question_3_solution[0]
    };

    boolean[] results = new boolean[solutions.length];
    for (int i = 0; i < solutions.length; i++) {
      if (givenAnswers[i].contains(solutions[i])) {
        // answer correct
        correctAnswers++;
        results[i] = true;
      } else {
        // answer incorrect
        results[i] = false;
      }
    }
    guesses.put(username, results);

    if (correctAnswers == solutions.length) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  @GetMapping("/cia/quiz")
  @ResponseBody
  public boolean[] getResults(@CurrentUsername String username) {
    return guesses.getOrDefault(username, new boolean[solutions.length]);
  }
}
