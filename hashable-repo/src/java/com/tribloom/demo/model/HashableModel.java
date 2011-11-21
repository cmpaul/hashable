package com.tribloom.demo.model;

import org.alfresco.service.namespace.QName;

public interface HashableModel {
	static final String DEMO_URI = "http://www.tribloom.com/model/demo/1.0";
	static final QName ASPECT_HASHABLE = QName.createQName(DEMO_URI, "hashable");
	static final QName PROP_HASH_TYPE = QName.createQName(DEMO_URI, "hashType");
	static final QName PROP_HASH_VALUE = QName.createQName(DEMO_URI, "hashValue");
}
