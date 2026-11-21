/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Base64;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import io.micrometer.common.lang.Nullable;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final RestTemplate restTemplate;
  private final String webWolfHost;
  private final String webWolfPort;
  private final String webWolfURL;
  private final String resetLinkHost;
  private final String mailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webgoat.url}") String webGoatURL,
      @Value("${webgoat.mail.url}") String mailURL) {
    this.restTemplate = restTemplate;
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfURL = webWolfURL;
    this.resetLinkHost = advertisedHost(webGoatURL);
    this.mailURL = mailURL;
  }

  private static String advertisedHost(String webGoatURL) {
    URI uri = URI.create(webGoatURL);
    String host = uri.getHost();
    int port = uri.getPort();
    return port == -1 ? host : host + ":" + port;
  }

  private static String createResetLink() {
    byte[] token = new byte[32];
    SECURE_RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }

  @Nullable
  private static String resolveDNSOrNull(String hostname){
      try {
          return InetAddress.getByName(hostname.split(":")[0]).getHostAddress();
      } catch (UnknownHostException e) {
          return null;
      }
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request, @CurrentUsername String username) {
    String resetLink = createResetLink();
    ResetLinkAssignment.resetLinks.add(resetLink);
    String host = request.getHeader(HttpHeaders.HOST);
    boolean hostChangedToWebWolf =
        host != null
            && host.contains(webWolfPort)
            && (host.contains(webWolfHost) || webWolfHost.equals(resolveDNSOrNull(host)));
    if (ResetLinkAssignment.TOM_EMAIL.equals(email) && hostChangedToWebWolf) {
      ResetLinkAssignment.userToTomResetLink.put(username, resetLink);
      fakeClickingLinkEmail(webWolfURL, resetLink);
    } else {
      try {
        sendMailToUser(email, resetLink);
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, resetLinkHost, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(mailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String webWolfURL, String resetLink) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity httpEntity = new HttpEntity(httpHeaders);
      new RestTemplate()
          .exchange(
              String.format("%s/PasswordReset/reset/reset-password/%s", webWolfURL, resetLink),
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (Exception e) {
      // don't care
    }
  }
}
