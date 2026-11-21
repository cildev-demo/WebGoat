/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge2;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NorthstarEndpoints {

  private static final String PUBLISHER_SITE = "https://example.org";
  private static final String FEED_PATH = "/northstar/feeds";
  private static final String REDIRECT_PATH = "/northstar/go";
  private static final String CONTEXT_FEED_PATH = "/WebGoat/northstar/feeds";
  private static final String CONTEXT_REDIRECT_PATH = "/WebGoat/northstar/go";

  @GetMapping("/northstar/go")
  public ResponseEntity<Void> redirect(@RequestParam String url) {
    if (PUBLISHER_SITE.equals(url)) {
      return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(PUBLISHER_SITE)).build();
    }
    if (FEED_PATH.equals(url)) {
      return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(FEED_PATH)).build();
    }
    if (REDIRECT_PATH.equals(url)) {
      return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(REDIRECT_PATH)).build();
    }
    if (CONTEXT_FEED_PATH.equals(url)) {
      return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(CONTEXT_FEED_PATH)).build();
    }
    if (CONTEXT_REDIRECT_PATH.equals(url)) {
      return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(CONTEXT_REDIRECT_PATH)).build();
    }
    return ResponseEntity.badRequest().build();
  }

  @GetMapping("/northstar/feeds")
  public String feeds() {
    return "Partner bulletin: the evening edition is ready for review.";
  }
}
