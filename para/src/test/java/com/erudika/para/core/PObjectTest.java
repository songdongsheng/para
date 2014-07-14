/*
 * Copyright 2013-2014 Erudika. http://erudika.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For issues and patches go to: https://github.com/erudika
 */
package com.erudika.para.core;

import com.erudika.para.persistence.DAO;
import com.erudika.para.persistence.MockDAO;
import com.erudika.para.search.Search;
import com.erudika.para.utils.Utils;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 *
 * @author Alex Bogdanovski [alex@erudika.com]
 */
public class PObjectTest {

	@Test
	public void testGetType() {
		Tag tag = new Tag();
		PObject p = new PObject() { };
		assertNotNull(tag.getType());
		assertNotNull(p.getType());
		assertEquals("", p.getType());
		assertEquals("tag", tag.getType());
		assertEquals("", p.getType());
	}

	@Test
	public void testGetObjectURI() {
		assertEquals("/tags/tag", new Tag("tag").getObjectURI());
		assertEquals("/users/1", new User("1").getObjectURI());
		assertEquals("/votes", new Vote(null,null,null).getObjectURI());
	}

	@Test
	public void testLinks() {
		Search search = mock(Search.class);
		DAO dao = new MockDAO();

		Tag t = new Tag("tag");
		User u = new User("111");
		User u3 = new User("333");

		u.setDao(dao);
		u.setSearch(search);

		dao.create(t);
		dao.create(u);
		dao.create(u3);

		Linker l1 = new Linker(Utils.type(User.class), Utils.type(Tag.class), "111", "222");
		Linker l2 = new Linker(Utils.type(User.class), Utils.type(User.class), "111", "333");

		u.link(t.getId());
		u.link(u3.getId());

		assertTrue(u.isLinked(t));
		assertTrue(u.isLinked(u3));

		ArrayList<ParaObject> list = new ArrayList<ParaObject>();
		list.add(l1);
		list.add(l2);

		when(search.findTerms(anyString(), anyString(), anyMapOf(String.class, Object.class),
				anyBoolean())).thenReturn(list);

		assertEquals(0, u.getLinkedObjects(Utils.type(Tag.class), null, null).size());
		assertEquals(0, u.getLinkedObjects(Utils.type(User.class), null, null).size());

		u.unlinkAll();

		assertNull(dao.read(l1.getId()));
		assertNull(dao.read(l2.getId()));
	}

	@Test
	public void testType() {
		assertEquals("user", Utils.type(User.class));
		assertEquals("tag", Utils.type(Tag.class));
		assertEquals("paraobject", Utils.type(ParaObject.class));
		assertEquals("vote", Utils.type(Vote.class));
		assertEquals("", Utils.type(null));
	}

	@Test
	public void testGetPlural() {
		assertEquals("users", new User().getPlural());
		assertEquals("addresses", new Address().getPlural());
		assertEquals("votes", new Vote().getPlural());
		assertEquals("linkers", new Linker().getPlural());
	}

	@Test
	public void testEquals() {
		User u1 = new User("111");
		User u2 = new User("111");
		assertTrue(u1.equals(u2));
	}

	@Test
	public void testAddRemoveTags() {
		User u1 = new User("111");
		List<String> someTags = new ArrayList<String>();
		someTags.add("one");
		someTags.add("two");
		someTags.add("");
		someTags.add(" ");
		someTags.add(null);
		List<String> cleanTags = new ArrayList<String>();
		cleanTags.add("one");
		cleanTags.add("two");
		u1.setTags(someTags);
		assertFalse(u1.getTags().contains(""));
		assertFalse(u1.getTags().contains(" "));
		assertFalse(u1.getTags().contains(null));
		assertEquals(cleanTags, u1.getTags());
		u1.addTags();
		u1.addTags(null, null, null);
		u1.addTags("two", "two", "two");
		assertEquals(cleanTags, u1.getTags());
		u1.addTags("three", "four", "five");
		assertEquals(5, u1.getTags().size());

		u1.removeTags("two", "four");
		assertEquals(3, u1.getTags().size());
		assertFalse(u1.getTags().contains("two"));
		assertFalse(u1.getTags().contains("four"));

		u1.addTags("one", "five");
		assertEquals(3, u1.getTags().size());
		u1.removeTags("two");
		assertEquals(3, u1.getTags().size());
		u1.removeTags(null, null);

		u1.setTags(null);
		assertNull(u1.getTags());
	}

	@Test
	public void testGetSetShardKey() {
		User u1 = new User("111");
		assertEquals(u1.getId(), u1.getShardKey());
		u1.setShardKey("somekey");
		assertEquals("somekey", u1.getShardKey());
	}
}