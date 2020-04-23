/*
 * Copyright 2017 Decipher Technology Studios LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.deciphernow.maven.plugins.bouncycastle;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.handler.ArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.codehaus.plexus.util.FileUtils;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides a Mojo that creates signature files the artifacts of a Maven project.
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.VERIFY)
public class SignMojo extends AbstractMojo {

  @Parameter(property = "rings")
  private String rings;

  @Parameter(property = "secretKeyring")
  private File secretKeyring;

  @Parameter(property = "passphrase")
  private String passphrase;

  @Parameter(property = "passphraseServerId")
  private String passphraseServerId;

  @Parameter(defaultValue = "${project}", readonly = true)
  private MavenProject project;

  @Parameter(property = "userId", required = true)
  private String userId;

  @Component
  private MavenProjectHelper projectHelper;

  @Parameter(defaultValue = "${settings}", readonly = true, required = true)
  private Settings settings;

  @Component(role = org.sonatype.plexus.components.sec.dispatcher.SecDispatcher.class, hint = "default")
  private SecDispatcher securityDispatcher;

  /**
   * Creates a detached signature file for all of the artifacts in this project.
   *
   * @throws MojoExecutionException if an unexpected error occurs
   * @throws MojoFailureException if an expected error occurs
   */
  public void execute() throws MojoExecutionException, MojoFailureException {

    ensureMojoConfigurationIsValid();

    if (passphraseServerId != null) {
      passphrase = getPassphraseFromMavenSettings();
    }

    if (secretKeyring != null) {
      rings = getKeyringFromFile();
    }

    try (InputStream inputStream = new ByteArrayInputStream(this.rings.getBytes(StandardCharsets.UTF_8))) {
      PGPSecretKeyRingCollection rings = Utils.loadSecretKeyRings(inputStream);
      PGPSecretKey key = Utils.find(this.userId, rings);
      List<SignedArtifact> signedArtifacts = new ArrayList<>();
      signedArtifacts.addAll(signMainArtifact(key));
      signedArtifacts.addAll(signAttachedArtifacts(key));
      signedArtifacts.add(signPomArtifact(key));
      signedArtifacts.forEach(SignedArtifact::attach);
    } catch (Exception exception) {
      throw new MojoExecutionException("Failed to execute sign mojo", exception);
    }
  }

  private void sign(File artifactFile, File signatureFile, PGPSecretKey key) throws IOException, PGPException {
    try (InputStream artifactStream = new FileInputStream(artifactFile);
         OutputStream signatureStream = new FileOutputStream(signatureFile)) {
      Utils.sign(artifactStream, signatureStream, key, this.passphrase);
    }
  }

  private File signArtifact(Artifact artifact, PGPSecretKey key) throws IOException, PGPException {
    File artifactFile = artifact.getFile();
    if (artifactFile != null && artifactFile.isFile()) {
      String signaturePath = String.format("%s.asc", artifactFile.getAbsolutePath());
      File signatureFile = new File(signaturePath);
      sign(artifactFile, signatureFile, key);
      return signatureFile;
    }
    return null;
  }

  private List<SignedArtifact> signMainArtifact(PGPSecretKey key) throws IOException, PGPException {
    List<SignedArtifact> signedArtifacts = new ArrayList<>();
    if (!project.getPackaging().equals("pom")) {
      Artifact artifact = project.getArtifact();
      File signatureFile = signArtifact(project.getArtifact(), key);
      signedArtifacts.add(new SignedArtifact(
              String.format("%s.asc", artifact.getArtifactHandler().getExtension()),
              null,
              signatureFile));
    }
    return signedArtifacts;
  }

  private List<SignedArtifact> signAttachedArtifacts(PGPSecretKey key) throws IOException, PGPException {
    List<SignedArtifact> signedArtifacts = new ArrayList<>();
    for (Object object : this.project.getAttachedArtifacts()) {
      Artifact artifact = (Artifact) object;
      File signatureFile = signArtifact(artifact, key);
      signedArtifacts.add(new SignedArtifact(
              String.format("%s.asc", artifact.getArtifactHandler().getExtension()),
              artifact.getClassifier(),
              signatureFile));
    }
    return signedArtifacts;
  }

  private SignedArtifact signPomArtifact(PGPSecretKey key) throws IOException, PGPException {
    Build build = project.getBuild();
    String pomPath = String.format("%s%s%s.pom", build.getDirectory(), File.separator, build.getFinalName());
    String signaturePath = String.format("%s.asc", pomPath);
    File pomFile = new File(pomPath);
    File signatureFile = new File(signaturePath);
    FileUtils.copyFile(project.getFile(), pomFile);
    sign(pomFile, signatureFile, key);
    return new SignedArtifact("pom.asc", null, signatureFile);
  }

  private String getPassphraseFromMavenSettings() throws MojoFailureException {

    Server server = settings.getServer(passphraseServerId);
    String value = server.getPassphrase();

    if (value == null) {
      throw new MojoFailureException("Unable to find passphrase in server " + passphraseServerId);
    }

    try {
      return securityDispatcher.decrypt(value);
    } catch (SecDispatcherException e) {
      throw new MojoFailureException("Unable to decode the passphrase of server " + passphraseServerId, e);
    }
  }

  private String getKeyringFromFile() throws MojoFailureException {
    try {
      byte[] encoded = Files.readAllBytes(Paths.get(secretKeyring.getPath()));
      return new String(encoded);
    } catch (IOException e) {
      throw new MojoFailureException("Unable to read keyring file " + secretKeyring, e);
    }
  }

  private void ensureMojoConfigurationIsValid() throws MojoFailureException {
    if (passphrase == null && passphraseServerId == null) {
      throw new MojoFailureException("'passphrase' or 'passphraseServerId' property is missing");
    }

    if (rings == null && secretKeyring == null) {
      throw new MojoFailureException("'rings' or 'secretKeyring' property is missing");
    }
  }

  private class SignedArtifact {

    private String artifactClassifier;

    private File artifactFile;

    private String artifactType;

    private SignedArtifact(String artifactType, String artifactClassifier, File artifactFile) {
      this.artifactClassifier = artifactClassifier;
      this.artifactFile = artifactFile;
      this.artifactType = artifactType;
    }

    private void attach() {
      SignMojo.this.projectHelper.attachArtifact(SignMojo.this.project, artifactType, artifactClassifier, artifactFile);
    }
  }
}
