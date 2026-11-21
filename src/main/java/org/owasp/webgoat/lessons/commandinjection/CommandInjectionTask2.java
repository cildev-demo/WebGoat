/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.owasp.webgoat.lessons.commandinjection.CommandExecutionService.CommandExecutionResult;
import org.owasp.webgoat.container.CurrentUser;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Task 2: demonstrate simple command chaining injection. */
@RestController
@AssignmentHints({"commandinjection.task2.hint1", "commandinjection.task2.hint2"})
public class CommandInjectionTask2 implements AssignmentEndpoint {

  static final String LEAKED_TOKEN =
      String.format(Locale.ROOT, "WEBGOAT_BUILD_TOKEN=%s", UUID.randomUUID().toString());

  private final CommandExecutionService commandExecutionService;
  private final CommandInjectionSafetyService safetyService;

  public CommandInjectionTask2(
      CommandExecutionService commandExecutionService,
      CommandInjectionSafetyService safetyService) {
    this.commandExecutionService = commandExecutionService;
    this.safetyService = safetyService;
  }

  @PostMapping(
      value = "/CommandInjection/task2/run",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public AttackResult run(
      @CurrentUser WebGoatUser user,
      @RequestParam("base") String baseCommand,
      @RequestParam("payload") String payload,
      @RequestParam(value = "token", required = false) String token) {

    safetyService.requireAcknowledgement(user);
    if (payload != null && !payload.isBlank()) {
      throw invalidRequest();
    }

    String requested = baseCommand == null ? "" : baseCommand.trim();
    List<String> command;
    if (requested.isEmpty()) {
      command = CommandExecutionService.isWindows() ? List.of("ver") : List.of("uname", "-a");
    } else if ("ver".equals(requested)) {
      command = List.of("ver");
    } else if ("uname -a".equals(requested)) {
      command = List.of("uname", "-a");
    } else if ("uname".equals(requested)) {
      command = List.of("uname");
    } else if ("hostname".equals(requested)) {
      command = List.of("hostname");
    } else if ("uptime".equals(requested)) {
      command = List.of("uptime");
    } else if ("whoami".equals(requested)) {
      command = List.of("whoami");
    } else if ("pwd".equals(requested)) {
      command = List.of("pwd");
    } else if ("id".equals(requested)) {
      command = List.of("id");
    } else if ("date".equals(requested)) {
      command = List.of("date");
    } else {
      throw invalidRequest();
    }

    CommandExecutionResult result =
        commandExecutionService.executeDirect(null, command, Map.of());
    String output = formatOutput(result);

    if (token == null || token.isBlank()) {
      return failed(this).feedback("commandinjection.task2.failure.blank").output(output).build();
    }

    if (matchesToken(token)) {
      return success(this).feedback("commandinjection.task2.success").output(output).build();
    }

    return failed(this).feedback("commandinjection.task2.failure.mismatch").output(output).build();
  }

  String buildCommand(String base, String payload) {
    if (payload != null && !payload.isBlank()) {
      throw invalidRequest();
    }
    String requested = base == null ? "" : base.trim();
    if (requested.isEmpty()) {
      return CommandExecutionService.isWindows() ? "ver" : "uname -a";
    }
    return switch (requested) {
      case "ver" -> "ver";
      case "uname -a" -> "uname -a";
      case "uname" -> "uname";
      case "hostname" -> "hostname";
      case "uptime" -> "uptime";
      case "whoami" -> "whoami";
      case "pwd" -> "pwd";
      case "id" -> "id";
      case "date" -> "date";
      default -> throw invalidRequest();
    };
  }

  private ResponseStatusException invalidRequest() {
    return new ResponseStatusException(
        HttpStatus.BAD_REQUEST, "commandinjection.task2.failure.mismatch");
  }

  boolean matchesToken(String submittedToken) {
    String value = submittedToken.trim();
    String tokenWithoutName = LEAKED_TOKEN.substring(LEAKED_TOKEN.indexOf('=') + 1);
    return value.equals(LEAKED_TOKEN) || value.equals(tokenWithoutName);
  }

  private String formatOutput(CommandExecutionResult result) {
    StringBuilder console = new StringBuilder();
    console.append("Command: ").append(result.command()).append("\n");
    console.append(result.output());
    if (result.timedOut()) {
      console.append("\n[Process terminated after timeout]\n");
    }
    if (result.executionError() != null) {
      console.append("\n[Execution error] ").append(result.executionError());
    }
    return console.toString();
  }
}
