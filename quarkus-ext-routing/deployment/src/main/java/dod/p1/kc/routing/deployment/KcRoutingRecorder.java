package dod.p1.kc.routing.deployment;

import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.logging.Log;
import java.util.Map;

@Recorder
public class KcRoutingRecorder {

    //CHECKSTYLE:OFF
    KcRoutingHandler handler;
    //CHECKSTYLE:ON

    /**
     *
     * @return handler
     */
    public KcRoutingHandler getHandler() {
        if (handler == null) {
            Log.debug("KcRoutingRecorder::getHandler() Creating new handle");
            handler = new KcRoutingHandler();
            return handler;
        } else {
          Log.debug("KcRoutingRecorder::getHandler() Returning existing handle");
          return handler;
        }

    }
    /**
     *
     * @param argPathRedirectsMap
     */
    public void setPathRedirects(final Map<String, String> argPathRedirectsMap) {
      Log.debugf("KcRoutingRecorder::setPathRedirects(%s) ", argPathRedirectsMap);
      if (handler != null) {
        KcRoutingHandler.setPathRedirects(argPathRedirectsMap);
      } else {
        Log.debug("KcRoutingRecorder::setPathRedirects(null)");
      }
    }

    /**
     *
     * @param argPathPrefixesMap
     */
    public void setPathPrefixes(final Map<String, String> argPathPrefixesMap) {
      Log.debugf("KcRoutingRecorder::setPathPrefixes(%s) ", argPathPrefixesMap);
      if (handler != null) {
        KcRoutingHandler.setPathPrefixes(argPathPrefixesMap);
      } else {
        Log.debug("KcRoutingRecorder::setPathPrefixes(null)");
      }
    }

    /**
     *
     * @param argPathFiltersMap
     */
    public void setPathFilters(final Map<String, String> argPathFiltersMap) {
      Log.debugf("KcRoutingRecorder::setPathFilters(%s) ", argPathFiltersMap);
      if (handler != null) {
        KcRoutingHandler.setPathFilters(argPathFiltersMap);
      } else {
        Log.debug("KcRoutingRecorder::setPathFilters(null)");
      }
    }

    /**
     *
     * @param argPathBlocksMap
     */
    public void setPathBlocks(final Map<String, String> argPathBlocksMap) {
      Log.debugf("KcRoutingRecorder::setPathBlocks(%s) ", argPathBlocksMap);
      if (handler != null) {
        KcRoutingHandler.setPathBlocks(argPathBlocksMap);
      } else {
        Log.debug("KcRoutingRecorder::setPathBlocks(null)");
      }
    }

    /**
     *
     * @param argPathRecursiveBlocksMap
     */
    public void setPathRecursiveBlocks(final Map<String, String> argPathRecursiveBlocksMap) {
      Log.debugf("KcRoutingRecorder::setPathRecursiveBlocks(%s) ", argPathRecursiveBlocksMap);
      if (handler != null) {
        KcRoutingHandler.setPathRecursiveBlocks(argPathRecursiveBlocksMap);
      } else {
        Log.debug("KcRoutingRecorder::setPathRecursiveBlocks(null)");
      }
    }

    /**
     *
     * @param argPathAllowsMap
     */
    public void setPathAllows(final Map<String, String> argPathAllowsMap) {
      Log.debugf("KcRoutingRecorder::setPathAllows(%s) ", argPathAllowsMap);
      if (handler != null) {
        KcRoutingHandler.setPathAllows(argPathAllowsMap);
      } else {
        Log.debug("KcRoutingRecorder::setPathAllows(null)");
      }
    }
}