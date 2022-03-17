import _ from "lodash";
import React, { FC, useEffect, useLayoutEffect, useRef, useState } from "react";
import { CONTAINER_AND_MARGIN_SIZE } from "./model";
import { Page } from "./Page";
import { PageCache } from "./PageCache";
import styles from "./VirtualScroll.module.css";

type VirtualScrollProps = {
  uri: string;
  query?: string;
  impromptuQuery?: string;
  triggerRefresh: number;

  totalPages: number;
  jumpToPage: number | null;
  preloadPages: number[];
  setMiddlePage: (n: number) => void;
};

export const VirtualScroll: FC<VirtualScrollProps> = ({
  uri,
  query,
  impromptuQuery,
  triggerRefresh: triggerHighlightRefresh,

  totalPages,
  jumpToPage,
  preloadPages,
  setMiddlePage,
}) => {
  // Tweaked this and 2 seems to be a good amount on a regular monitor
  // The fewer pages we preload the faster the initial paint will be
  // Could possibly make it dynamic based on the visible of the container
  const PRELOAD_PAGES = 2;

  const pageHeight = CONTAINER_AND_MARGIN_SIZE;

  const viewport = useRef<HTMLDivElement>(null);

  const [pageCache] = useState(new PageCache(uri, query));

  // We have a second tier cache tied to the React component lifecycle for storing
  // rendered pages which allows us to swap out stale pages without flickering pages
  const [currentPages, setCurrentPages] = useState<any[]>([]);

  useEffect(() => {
    pageCache.setImpromptuQuery(impromptuQuery);
  }, [impromptuQuery]);

  const [topPage, setTopPage] = useState(1);
  const [midPage, setMidPage] = useState(1); // Todo hook up to URL
  const [botPage, setBotPage] = useState(1 + PRELOAD_PAGES);

  const getPages = () => {
    if (viewport?.current) {
      const v = viewport.current;

      const currentMid = v.scrollTop + v.clientHeight / 2;

      const topEdge = currentMid - PRELOAD_PAGES * pageHeight;
      const botEdge = currentMid + PRELOAD_PAGES * pageHeight;

      const newTopPage = Math.max(Math.floor(topEdge / pageHeight), 1);
      const newMidPage = Math.floor(currentMid / pageHeight) + 1;
      const newBotPage = Math.min(Math.ceil(botEdge / pageHeight), totalPages);

      setTopPage(newTopPage);
      setMidPage(newMidPage);
      setBotPage(newBotPage);

      // Inform the parent component of the new middle page
      // This allows it to do useful things such as have a sensible "next" page
      // to go to for the impromptu hits
      setMiddlePage(newMidPage);
    }
  };

  const onScroll = () => {
    getPages();
  };

  useEffect(() => {
    getPages();
  }, [viewport]);

  useLayoutEffect(() => {
    if (viewport?.current && jumpToPage) {
      const v = viewport.current;
      const scrollTo = (jumpToPage - 1) * pageHeight;
      v.scrollTop = scrollTo;
    }
  }, [pageHeight, jumpToPage]);

  useEffect(() => {
    const renderedPages = _.range(topPage, botPage + 1).map((pageNumber) => {
      const cachedPage = pageCache.getPage(pageNumber);
      return {
        pageNumber,
        getPagePreview: cachedPage.preview,
        getPageData: cachedPage.data,
      };
    });

    setCurrentPages(renderedPages);
  }, [midPage]);

  useLayoutEffect(() => {
    if (triggerHighlightRefresh > 0) {
      const renderedPages = currentPages.map((page) => {
        // TODO This currently refetches the preview too which is pointless...
        const refreshedPage = pageCache.getPageRefreshHighlights(
          page.pageNumber
        );
        return {
          pageNumber: page.pageNumber,
          getPagePreview: page.getPagePreview,
          getPageData: refreshedPage.data,
        };
      });

      preloadPages.forEach((p) => pageCache.getPageRefreshHighlights(p));

      setCurrentPages(renderedPages);
    }
  }, [triggerHighlightRefresh]);

  useEffect(() => {
    preloadPages.forEach((p) => pageCache.getPage(p));
  }, [preloadPages]);

  return (
    <div ref={viewport} className={styles.scrollContainer} onScroll={onScroll}>
      <div className={styles.pages} style={{ height: totalPages * pageHeight }}>
        {currentPages.map((page) => (
          <div
            key={page.pageNumber}
            style={{ top: (page.pageNumber - 1) * pageHeight }}
            className={styles.pageContainer}
          >
            <Page
              pageNumber={page.pageNumber}
              getPagePreview={page.getPagePreview}
              getPageData={page.getPageData}
            />
          </div>
        ))}
      </div>
    </div>
  );
};
