﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


namespace Microsoft.IIS.Administration.Tests
{
    using Administration.Files;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using Web.Administration;
    using Xunit;

    public class Files
    {
        private const string TEST_FILE_NAME = "TEST_FILE.txt";
        private const string FILE_TEST_SITE_NAME = "File Test Site";
        private const string WEBSERVER_FILES_PATH = "/api/webserver/files";

        [Fact]
        public void ResolveApplication()
        {
            using (var sm = new ServerManager()) {
                var site = sm.Sites.CreateElement();
                var app = site.Applications.CreateElement();
                app.Path = "/";
                site.Applications.Add(app);
                app = site.Applications.CreateElement();
                app.Path = "/a";
                site.Applications.Add(app);
                app = site.Applications.CreateElement();
                app.Path = "/a/b";
                site.Applications.Add(app);
                app = site.Applications.CreateElement();
                app.Path = "/b";
                site.Applications.Add(app);
                app = site.Applications.CreateElement();
                app.Path = "/ac/b";
                site.Applications.Add(app);

                app = WebServer.Files.FilesHelper.ResolveApplication(site, "/");
                Assert.True(app.Path == "/");

                app = WebServer.Files.FilesHelper.ResolveApplication(site, "/ac");
                Assert.True(app.Path == "/");

                app = WebServer.Files.FilesHelper.ResolveApplication(site, "/a");
                Assert.True(app.Path == "/a");

                app = WebServer.Files.FilesHelper.ResolveApplication(site, "/a/c");
                Assert.True(app.Path == "/a");

                app = WebServer.Files.FilesHelper.ResolveApplication(site, "/a/bc");
                Assert.True(app.Path == "/a");

                app = WebServer.Files.FilesHelper.ResolveApplication(site, "/a/b/c");
                Assert.True(app.Path == "/a/b");
            }
        }

        [Fact]
        public void ResolveVdir()
        {
            using (var sm = new ServerManager()) {
                var site = sm.Sites.CreateElement();
                var app1 = site.Applications.CreateElement();
                app1.Path = "/app1";
                site.Applications.Add(app1);
                var app2 = site.Applications.CreateElement();
                app2.Path = "/app2";
                site.Applications.Add(app2);

                var vdir = app1.VirtualDirectories.CreateElement();
                vdir.Path = "/";
                app1.VirtualDirectories.Add(vdir);
                vdir = app1.VirtualDirectories.CreateElement();
                vdir.Path = "/vdir1";
                app1.VirtualDirectories.Add(vdir);

                vdir = WebServer.Files.FilesHelper.ResolveVdir(site, "/app1/vdir1");
                Assert.True(vdir.Path == "/vdir1");
                vdir = WebServer.Files.FilesHelper.ResolveVdir(site, "/app1/a_folder");
                Assert.True(vdir.Path == "/");
            }
        }

        [Fact]
        public void IsParentPath()
        {
            Assert.True(PathUtil.IsParentPath("/", "/a"));
            Assert.True(PathUtil.IsParentPath("/a/b", "/a/b/c"));
            Assert.False(PathUtil.IsParentPath("/", "/"));
            Assert.False(PathUtil.IsParentPath("/a/b", "/a/bc"));
        }

        [Fact]
        public void IsExactVdirPath()
        {
            using (var sm = new ServerManager()) {
                var site = sm.Sites.CreateElement();

                var app1 = site.Applications.CreateElement();
                app1.Path = "/app1";

                var vdir1a = app1.VirtualDirectories.CreateElement();
                vdir1a.Path = "/";
                app1.VirtualDirectories.Add(vdir1a);
                var vdir1b = app1.VirtualDirectories.CreateElement();
                vdir1b.Path = "/vdir1b";
                app1.VirtualDirectories.Add(vdir1b);
                site.Applications.Add(app1);

                var app2 = site.Applications.CreateElement();
                app2.Path = "/app2";
                var vdir2a = app2.VirtualDirectories.CreateElement();
                vdir2a.Path = "/";
                app2.VirtualDirectories.Add(vdir2a);
                var vdir2b = app2.VirtualDirectories.CreateElement();
                vdir2b.Path = "/vdir2b";
                app2.VirtualDirectories.Add(vdir2b);
                site.Applications.Add(app2);

                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1a, "/app1/"));
                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1a, "/app1"));
                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1b, "/app1/vdir1b"));
                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1b, "/app1/vdir1b/"));

                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app2, vdir2a, "/app2"));
                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app2, vdir2a, "/app2/"));
                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app2, vdir2b, "/app2/vdir2b"));
                Assert.True(WebServer.Files.FilesHelper.IsExactVdirPath(site, app2, vdir2b, "/app2/vdir2b/"));

                Assert.False(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1a, "/app1/folder"));
                Assert.False(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1b, "/app1/vdir1b/folder"));
                Assert.False(WebServer.Files.FilesHelper.IsExactVdirPath(site, app1, vdir1b, "/app2/vdir1b"));
            }
        }

        [Fact]
        public void GetPhysicalPath()
        {
            using (var sm = new ServerManager()) {
                var site = sm.Sites.CreateElement();

                var rootApp = site.Applications.CreateElement();
                rootApp.Path = "/";
                var rootVdir = rootApp.VirtualDirectories.CreateElement();
                rootVdir.Path = "/";
                rootApp.VirtualDirectories.Add(rootVdir);
                site.Applications.Add(rootApp);

                var app1 = site.Applications.CreateElement();
                app1.Path = "/app1";
                var vdir1a = app1.VirtualDirectories.CreateElement();
                vdir1a.Path = "/";
                app1.VirtualDirectories.Add(vdir1a);
                var vdir1b = app1.VirtualDirectories.CreateElement();
                vdir1b.Path = "/vdir1b";
                app1.VirtualDirectories.Add(vdir1b);
                site.Applications.Add(app1);

                const string rootVdirPhysicalPath = @"c:\sites\physicalPathSite";
                const string vdir1aPhysicalPath = @"c:\storage\test_site\app1";
                const string vdir1bPhysicalPath = @"c:\storage\test_site\app1\vdir1b";
                rootVdir.PhysicalPath = rootVdirPhysicalPath;
                vdir1a.PhysicalPath = vdir1aPhysicalPath;
                vdir1b.PhysicalPath = vdir1bPhysicalPath;

                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/"), rootVdirPhysicalPath);
                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/abc/defg"), rootVdirPhysicalPath + @"\abc\defg");
                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/app1"), vdir1aPhysicalPath);
                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/app1/abc/defg"), vdir1aPhysicalPath + @"\abc\defg");
                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/app1/vdir1bc/abc/defg"), vdir1aPhysicalPath + @"\vdir1bc\abc\defg");
                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/app1/vdir1b"), vdir1bPhysicalPath);
                Assert.Equal(WebServer.Files.FilesHelper.GetPhysicalPath(site, "/app1/vdir1b/abc/defg"), vdir1bPhysicalPath + @"\abc\defg");
            }
        }

        [Fact]
        public void IsValidFileName()
        {
            var goodFileNames = new string[]
            {
                "abc",
                "abc.def",
                ".abc",
                "a.b.c.-g_r.z"
            };

            var badFileNames = new string[]
            {
                ".",
                "..",
                "/./",
                "/../",
                "../",
                "/..",
                "\\abc",
                "abc\\",
                "/abc",
                "*a",
                "abc/",
                "....",
                "abc.",
            };

            foreach (var name in goodFileNames) {
                Assert.True(PathUtil.IsValidFileName(name));
            }

            foreach (var name in badFileNames) {
                Assert.False(PathUtil.IsValidFileName(name));
            }
        }

        [Fact]
        public void PrefixSegments()
        {
            var path = "/";

            Assert.Equal(PathUtil.PrefixSegments("/", path), 1);
            Assert.Equal(PathUtil.PrefixSegments("/a", path), -1);

            path = "/abc/def/ghi";

            Assert.Equal(PathUtil.PrefixSegments("/", path), 1);
            Assert.Equal(PathUtil.PrefixSegments("/abc", path), 2);
            Assert.Equal(PathUtil.PrefixSegments("/abc/", path), 2);
            Assert.Equal(PathUtil.PrefixSegments("/abcd/", path), -1);
            Assert.Equal(PathUtil.PrefixSegments("/aBc/", path), 2);
            Assert.Equal(PathUtil.PrefixSegments("/aBc/", path, StringComparison.Ordinal), -1);
            Assert.Equal(PathUtil.PrefixSegments("/abc/def", path), 3);
            Assert.Equal(PathUtil.PrefixSegments("/abc/def/", path), 3);
            Assert.Equal(PathUtil.PrefixSegments("/abc/defg/", path), -1);
            Assert.Equal(PathUtil.PrefixSegments("/abca/def/", path), -1);

        }

        [Fact]
        public void RemoveLastSegment()
        {
            Assert.Equal(PathUtil.RemoveLastSegment("/a"), "/");
            Assert.Equal(PathUtil.RemoveLastSegment("/a/"), "/");
            Assert.Equal(PathUtil.RemoveLastSegment("/abc/def/ghi"), "/abc/def");
            Assert.Equal(PathUtil.RemoveLastSegment("/abc/def/ghi"), "/abc/def");
            Assert.Equal(PathUtil.RemoveLastSegment("/abc/def/ghi/"), "/abc/def");
            Assert.Equal(PathUtil.RemoveLastSegment(@"/abc/def\ghi"), "/abc/def");
            Assert.Equal(PathUtil.RemoveLastSegment(@"/abc/def\ghi/"), "/abc/def");
            Assert.Equal(PathUtil.RemoveLastSegment(@"/abc/def\ghi\"), "/abc/def");
        }

        [Fact]
        public void CreateEditDeleteFile()
        {
            using (HttpClient client = ApiHttpClient.Create()) {

                JObject site = Sites.GetSite(client, "Default Web Site");

                var physicalPath = site.Value<string>("physical_path");

                if (File.Exists(Path.Combine(physicalPath, TEST_FILE_NAME))) {
                    File.Delete(Path.Combine(physicalPath, TEST_FILE_NAME));
                }

                var rootDir = Utils.FollowLink(client, site, "files");

                object newFile = new {
                    type = "file",
                    parent = rootDir,
                    name = TEST_FILE_NAME
                };

                // Create web file
                var webFile = client.Post($"{Configuration.TEST_SERVER_URL}{WEBSERVER_FILES_PATH}", newFile);

                Assert.True(webFile != null);

                try {
                    //
                    // Get physical file info
                    var fileInfo = Utils.FollowLink(client, webFile.Value<JObject>("file_info"), "self");

                    // Update content of file
                    var testContent = "Microsoft.IIS.Administration.Test.Files";
                    var res = client.PutAsync(Utils.GetLink(fileInfo, "content"), new StringContent(testContent)).Result;

                    Assert.True(res.StatusCode == HttpStatusCode.OK);

                    // Get updated content of file
                    string result = null;
                    Assert.True(client.Get(Utils.GetLink(fileInfo, "content"), out result));
                    Assert.True(result == testContent);

                    var downloadsHref = Utils.GetLink(fileInfo, "downloads");

                    var dl = new {
                        file = fileInfo
                    };

                    // Create download link for file
                    res = client.PostAsync(downloadsHref, new StringContent(JsonConvert.SerializeObject(dl), Encoding.UTF8, "application/json")).Result;
                    Assert.True(res.StatusCode == HttpStatusCode.Created);

                    IEnumerable<string> locationHeader;
                    Assert.True(res.Headers.TryGetValues("location", out locationHeader));
                    var location = locationHeader.First();

                    // Download file
                    Assert.True(client.Get($"{Configuration.TEST_SERVER_URL}{location}", out result));
                    Assert.True(result == testContent);
                }
                finally {
                    Assert.True(client.Delete(Utils.Self(webFile)));
                }
            }
        }

        [Fact]
        public void RangeUploadDownload()
        {
            using (HttpClient client = ApiHttpClient.Create()) {

                JObject site = Sites.GetSite(client, "Default Web Site");

                // Create web file
                var webFile = CreateWebFile(client, site, TEST_FILE_NAME);

                try {
                    //
                    // Get physical file info
                    var fileInfo = Utils.FollowLink(client, webFile.Value<JObject>("file_info"), "self");

                    var chunkSize = 4096;
                    var totalFileSize = 1024 * 1024;
                    HttpRequestMessage req;
                    HttpResponseMessage res;

                    for (var i = 0; i < totalFileSize; i+= chunkSize) {
                        req = new HttpRequestMessage(HttpMethod.Put, Utils.GetLink(fileInfo, "content"));

                        var currentChunkSize = totalFileSize - i < chunkSize ? totalFileSize - i : chunkSize;
                        var slice = GetFileSlice(i, currentChunkSize);

                        req.Content = new ByteArrayContent(slice);

                        req.Content.Headers.Add("Content-Range", $"bytes {i}-{i + currentChunkSize - 1}/{totalFileSize}");

                        res = client.SendAsync(req).Result;

                        Assert.True(Globals.Success(res));
                    }

                    req = new HttpRequestMessage(HttpMethod.Get, Utils.GetLink(fileInfo, "content"));

                    res = client.SendAsync(req).Result;

                    Assert.True(Globals.Success(res));

                    var resultBytes = res.Content.ReadAsByteArrayAsync().Result;

                    Assert.True(resultBytes.SequenceEqual(GetFileSlice(0, totalFileSize)));

                    var download = new byte[totalFileSize];

                    //
                    // Range download
                    for (var i = 0; i < totalFileSize; i += chunkSize) {
                        req = new HttpRequestMessage(HttpMethod.Get, Utils.GetLink(fileInfo, "content"));

                        var currentChunkSize = totalFileSize - i < chunkSize ? totalFileSize - i : chunkSize;

                        req.Headers.Add("Range", $"bytes={i}-{i + currentChunkSize - 1}");

                        res = client.SendAsync(req).Result;

                        Assert.True(Globals.Success(res));

                        resultBytes = res.Content.ReadAsByteArrayAsync().Result;
                        resultBytes.CopyTo(download, i);
                    }

                    Assert.True(download.SequenceEqual(GetFileSlice(0, totalFileSize)));
                }
                finally {
                    Assert.True(client.Delete(Utils.Self(webFile)));
                }
            }
        }



        private byte[] GetFileSlice(int start, int length)
        {
            var mod = byte.MaxValue + 1;
            var ret = new byte[length];
            byte initial = (byte)(start % mod);

            for (var i = 0; i < length; i++) {
                ret[i] = (byte)((initial + i) % mod);
            }

            return ret;
        }

        private JObject CreateWebFile(HttpClient client, JObject site, string fileName, string fileType = "file", bool deleteIfExists = true)
        {
            var physicalPath = site.Value<string>("physical_path");

            if (deleteIfExists && File.Exists(Path.Combine(physicalPath, TEST_FILE_NAME))) {
                File.Delete(Path.Combine(physicalPath, TEST_FILE_NAME));
            }

            var rootDir = Utils.FollowLink(client, site, "files");

            object newFile = new
            {
                type = fileType,
                parent = rootDir,
                name = fileName
            };

            // Create web file
            var webFile = client.Post($"{Configuration.TEST_SERVER_URL}{WEBSERVER_FILES_PATH}", newFile);

            Assert.True(webFile != null);

            return webFile;
        }
    }
}