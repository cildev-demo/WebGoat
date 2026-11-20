/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {
  private final File catPicturesDirectory;

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory = new File(webGoatHomeDirectory, "/PathTraversal/" + "/cats");
    this.catPicturesDirectory.mkdirs();
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
    var secretDirectory = this.catPicturesDirectory.getParentFile().getParentFile();
    try {
      Files.writeString(
          secretDirectory.toPath().resolve("path-traversal-secret.jpg"),
          "You found it submit the SHA-512 hash of your username as answer");
    } catch (IOException e) {
      log.error("Unable to write secret in: {}", secretDirectory, e);
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "secret", required = false) String secret,
      @CurrentUsername String username) {
    if (Sha512DigestUtils.shaHex(username).equalsIgnoreCase(secret)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    String id = request.getParameter("id");
    String catPictureName;
    if (id == null) {
      switch (RandomUtils.nextInt(1, 11)) {
        case 1:
          catPictureName = "1.jpg";
          break;
        case 2:
          catPictureName = "2.jpg";
          break;
        case 3:
          catPictureName = "3.jpg";
          break;
        case 4:
          catPictureName = "4.jpg";
          break;
        case 5:
          catPictureName = "5.jpg";
          break;
        case 6:
          catPictureName = "6.jpg";
          break;
        case 7:
          catPictureName = "7.jpg";
          break;
        case 8:
          catPictureName = "8.jpg";
          break;
        case 9:
          catPictureName = "9.jpg";
          break;
        default:
          catPictureName = "10.jpg";
      }
    } else {
      switch (id) {
        case "1":
        case "1.jpg":
          catPictureName = "1.jpg";
          break;
        case "2":
        case "2.jpg":
          catPictureName = "2.jpg";
          break;
        case "3":
        case "3.jpg":
          catPictureName = "3.jpg";
          break;
        case "4":
        case "4.jpg":
          catPictureName = "4.jpg";
          break;
        case "5":
        case "5.jpg":
          catPictureName = "5.jpg";
          break;
        case "6":
        case "6.jpg":
          catPictureName = "6.jpg";
          break;
        case "7":
        case "7.jpg":
          catPictureName = "7.jpg";
          break;
        case "8":
        case "8.jpg":
          catPictureName = "8.jpg";
          break;
        case "9":
        case "9.jpg":
          catPictureName = "9.jpg";
          break;
        case "10":
        case "10.jpg":
          catPictureName = "10.jpg";
          break;
        default:
          return ResponseEntity.badRequest().body("Invalid picture id");
      }
    }
    try {
      var catPicture = new File(catPicturesDirectory, catPictureName);

      if (catPicture.exists()) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getName()))
            .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
      }
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getName()))
          .body(
              StringUtils.arrayToCommaDelimitedString(catPicture.getParentFile().listFiles())
                  .getBytes());
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }

    return ResponseEntity.badRequest().build();
  }
}
