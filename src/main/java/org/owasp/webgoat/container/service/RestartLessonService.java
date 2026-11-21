/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
import java.util.function.Function;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.Flyway;
import org.owasp.webgoat.container.CurrentUser;
import org.owasp.webgoat.container.lessons.Initializable;
import org.owasp.webgoat.container.lessons.LessonName;
import org.owasp.webgoat.container.session.Course;
import org.owasp.webgoat.container.users.UserProgress;
import org.owasp.webgoat.container.users.UserProgressRepository;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;

@Controller
@AllArgsConstructor
@Slf4j
public class RestartLessonService {

  private final Course course;
  private final UserProgressRepository userTrackerRepository;
  private final Function<String, Flyway> flywayLessons;
  private final List<Initializable> lessonsToInitialize;

  @GetMapping(path = "/service/restartlesson.mvc/{lesson}")
  @ResponseStatus(value = HttpStatus.OK)
  public void restartLesson(
      @PathVariable("lesson") LessonName lessonName,
      @CurrentUser WebGoatUser user,
      HttpServletRequest request) {
    if (!isSameOrigin(request)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cross-origin request rejected");
    }

    var lesson = course.getLessonByName(lessonName);

    UserProgress userTracker = userTrackerRepository.findByUser(user.getUsername());
    userTracker.reset(lesson);
    userTrackerRepository.save(userTracker);

    var flyway = flywayLessons.apply(user.getUsername());
    flyway.clean();
    flyway.migrate();

    lessonsToInitialize.forEach(i -> i.initialize(user));
  }

  private boolean isSameOrigin(HttpServletRequest request) {
    String origin = trimToNull(request.getHeader("Origin"));
    if (origin != null) {
      return matchesRequestHost(request, origin);
    }
    String referer = trimToNull(request.getHeader("Referer"));
    return referer != null && matchesRequestHost(request, referer);
  }

  private boolean matchesRequestHost(HttpServletRequest request, String value) {
    URI expected = requestOrigin(request);
    if (expected == null) {
      return false;
    }
    try {
      URI actual = URI.create(value);
      return actual.getScheme() != null
          && actual.getHost() != null
          && actual.getUserInfo() == null
          && actual.getScheme().equalsIgnoreCase(expected.getScheme())
          && actual.getHost().equalsIgnoreCase(expected.getHost())
          && effectivePort(actual) == effectivePort(expected);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private URI requestOrigin(HttpServletRequest request) {
    String scheme = request.getScheme();
    if (scheme == null || scheme.isBlank()) {
      return null;
    }
    if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
      return null;
    }
    String authority = trimToNull(request.getHeader("Host"));
    if (authority == null) {
      String serverName = request.getServerName();
      if (serverName == null || serverName.isBlank()) {
        return null;
      }
      authority = serverName;
      if (serverName.indexOf(':') >= 0 && !serverName.startsWith("[")) {
        authority = "[" + serverName + "]";
      }
      int serverPort = request.getServerPort();
      if (serverPort > 0 && !isDefaultPort(scheme, serverPort)) {
        authority = authority + ":" + serverPort;
      }
    }
    try {
      return URI.create(scheme + "://" + authority);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private int effectivePort(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    if ("http".equalsIgnoreCase(uri.getScheme())) {
      return 80;
    }
    if ("https".equalsIgnoreCase(uri.getScheme())) {
      return 443;
    }
    return -1;
  }

  private boolean isDefaultPort(String scheme, int port) {
    return ("http".equalsIgnoreCase(scheme) && port == 80)
        || ("https".equalsIgnoreCase(scheme) && port == 443);
  }

  private String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }
}
