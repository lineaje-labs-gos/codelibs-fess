/*
 * Copyright 2012-2025 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.opensearch.client;

import org.codelibs.fess.unit.UnitFessTestCase;
import org.junit.jupiter.api.Test;

/**
 * Covers {@code readIndexSetting}'s document-index guard: the document settings rewrite rules
 * (registered by e.g. {@code ChunkVectorHelper} for the chunk vector codec/knn settings) must
 * only be applied to the document index, exactly like {@code addMapping} already does for the
 * mapping rules.
 */
public class SearchEngineClientIndexSettingTest extends UnitFessTestCase {

    private static final String DOC_INDEX_CONFIG = "fess_indices/fess.json";

    private static final String CONFIG_INDEX_CONFIG = "fess_indices/fess_config.web_config.json";

    @Test
    public void test_readIndexSetting_appliesRewriteOnlyToDocIndex() {
        final SearchEngineClient client = new SearchEngineClient();
        client.addDocumentSettingRewriteRule(source -> source + "/*REWRITE_MARKER*/");

        final String docSource = client.readIndexSetting("fess", "opensearch", DOC_INDEX_CONFIG, "5", "0-1");
        assertTrue(docSource.contains("/*REWRITE_MARKER*/"), "the document index must still receive the rewrite rules");

        // fess_indices holds 34 top-level settings files; applying the document rules to the other
        // 33 makes every anchor-miss warning point at fess.json, an unrelated file
        final String configSource = client.readIndexSetting("fess_config.web_config", "opensearch", CONFIG_INDEX_CONFIG, "5", "0-1");
        assertFalse(configSource.contains("/*REWRITE_MARKER*/"), "a non-document index must not receive the document rewrite rules");
    }

    @Test
    public void test_readIndexSetting_stillSubstitutesPlaceholders() {
        final SearchEngineClient client = new SearchEngineClient();
        // placeholder substitution is index-independent and must survive the guard
        final String docSource = client.readIndexSetting("fess", "opensearch", DOC_INDEX_CONFIG, "7", "0-2").replaceAll("\\s", "");
        assertTrue(docSource.contains("\"number_of_shards\":\"7\""), docSource);
        assertTrue(docSource.contains("\"auto_expand_replicas\":\"0-2\""), docSource);
        assertFalse(docSource.contains("${fess.index."), docSource);
        final String configSource = client.readIndexSetting("fess_config.web_config", "opensearch", CONFIG_INDEX_CONFIG, "7", "0-2");
        assertFalse(configSource.contains("${fess.index."), configSource);
    }
}
