/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
      }
      contact = parseContact(payload);
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-components.close")
          .output(HtmlUtils.htmlEscape(ex.getMessage()))
          .build();
    }

    try {
      if (null != contact) {
        contact.getFirstName();
      }
      if (!(contact instanceof ContactImpl)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
    } catch (Exception e) {
      return success(this)
          .feedback("vulnerable-components.success")
          .output(HtmlUtils.htmlEscape(e.getMessage()))
          .build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }

  private Contact parseContact(String payload) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

    DocumentBuilder builder = factory.newDocumentBuilder();
    builder.setEntityResolver(
        (publicId, systemId) -> {
          throw new SAXException("External entities are not allowed");
        });

    Document document = builder.parse(new InputSource(new StringReader(payload)));
    Element root = document.getDocumentElement();
    if (root == null || !"contact".equals(root.getTagName())) {
      throw new IllegalArgumentException("Expected a contact element");
    }

    ContactImpl contact = new ContactImpl();
    contact.setId(parseInteger(textOf(root, "id")));
    contact.setFirstName(textOf(root, "firstName"));
    contact.setLastName(textOf(root, "lastName"));
    contact.setEmail(textOf(root, "email"));
    return contact;
  }

  private static String textOf(Element root, String tagName) {
    NodeList nodes = root.getElementsByTagName(tagName);
    if (nodes.getLength() == 0) {
      return null;
    }
    Node node = nodes.item(0);
    return node == null ? null : node.getTextContent();
  }

  private static Integer parseInteger(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return Integer.valueOf(value.trim());
  }
}
