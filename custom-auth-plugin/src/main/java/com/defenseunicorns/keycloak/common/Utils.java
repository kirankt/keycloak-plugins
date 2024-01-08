package com.defenseunicorns.keycloak.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.jboss.logging.Logger;

/**
 * The sole purpose of this class is to allow for unit test coverage. The Jaccoco test coverage
 * report is not fully compatible with the PowerMock testing framework. This class is used in
 * @PrepareForTest so that the Jaccoco report detects test coverage for CommonConfig class.
 */
public final class Utils {

  public static final Logger LOGGER = Logger.getLogger(Utils.class);

  private Utils() {
    // hide public constructor. No need to ever declare an instance. All methods are static.
  }

  /**
   * Get new java.io.File object.
   *
   * @param filePath a String
   * @return File
   */
  public static File getFile(final String filePath) {
    return new File(filePath);
  }

  /**
   * Get new java.io.FileInputStream object.
   *
   * @param file a File object
   * @return FileInputStream
   */
  public static FileInputStream getFileInputStream(final File file) throws FileNotFoundException {
    return new FileInputStream(file);
  }

}
