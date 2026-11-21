/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Controller for fetching all the HTTP requests from WebGoat to WebWolf for a specific user.
 */
@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(value = "/requests")
public class Requests {

  private final WebWolfTraceRepository traceRepository;
  private final ObjectMapper objectMapper;

  @AllArgsConstructor
  @Getter
  private class Tracert {
    private final Instant date;
    private final String path;
    private final String json;
  }

  @GetMapping
  public ModelAndView get(Authentication authentication) {
    var model = new ModelAndView("requests");
    String username = (null != authentication) ? authentication.getName() : null;
    var traces =
        traceRepository.findAll().stream()
            .filter(t -> username != null && allowedTrace(t, username))
            .map(t -> new Tracert(t.getTimestamp(), path(t), toJsonString(t)))
            .toList();
    model.addObject("traces", traces);

    return model;
  }

  private boolean allowedTrace(HttpExchange t, String username) {
    String principalName = principalName(t);
    if (principalName != null) {
      return principalName.equals(username);
    }

    HttpExchange.Request req = t.getRequest();
    URI uri = req.getUri();
    String path = uri.getPath();
    if (isFilesPath(path)) {
      return isOwnedFile(path, username);
    }
    if (isLandingPath(path)) {
      return isOwnedLanding(uri, username);
    }
    return false;
  }

  private String principalName(HttpExchange t) {
    var principal = t.getPrincipal();
    return principal != null ? principal.getName() : null;
  }

  private boolean isFilesPath(String path) {
    return hasPathSegment(path, "files");
  }

  private boolean isLandingPath(String path) {
    return hasPathSegment(path, "landing");
  }

  private boolean hasPathSegment(String path, String segment) {
    if (path == null) {
      return false;
    }
    for (String part : path.split("/")) {
      if (segment.equals(part)) {
        return true;
      }
    }
    return false;
  }

  private boolean isOwnedFile(String path, String username) {
    if (path == null || username == null) {
      return false;
    }
    String[] parts = path.split("/");
    for (int i = 0; i < parts.length - 1; i++) {
      if ("files".equals(parts[i]) && username.equals(parts[i + 1])) {
        return true;
      }
    }
    return false;
  }

  private boolean isOwnedLanding(URI uri, String username) {
    List<String> codes =
        UriComponentsBuilder.fromUri(uri).build().getQueryParams().get("uniqueCode");
    if (codes == null || codes.isEmpty()) {
      return false;
    }
    String expectedCode = StringUtils.reverse(username);
    return codes.stream().anyMatch(expectedCode::equals);
  }

  private String path(HttpExchange t) {
    return t.getRequest().getUri().getPath();
  }

  private String toJsonString(HttpExchange t) {
    try {
      return objectMapper.writeValueAsString(sanitizedTrace(t));
    } catch (JsonProcessingException e) {
      log.error("Unable to create json", e);
    }
    return "No request(s) found";
  }

  private Map<String, Object> sanitizedTrace(HttpExchange t) {
    Map<String, Object> trace = new LinkedHashMap<>();
    trace.put("timestamp", t.getTimestamp());
    trace.put("timeTaken", t.getTimeTaken());

    HttpExchange.Request request = t.getRequest();
    Map<String, Object> safeRequest = new LinkedHashMap<>();
    safeRequest.put("method", request.getMethod());
    safeRequest.put("uri", request.getUri().toString());
    trace.put("request", safeRequest);

    var response = t.getResponse();
    if (response != null) {
      Map<String, Object> safeResponse = new LinkedHashMap<>();
      safeResponse.put("status", response.getStatus());
      trace.put("response", safeResponse);
    }

    String principalName = principalName(t);
    if (principalName != null) {
      trace.put("principal", principalName);
    }
    return trace;
  }
}
