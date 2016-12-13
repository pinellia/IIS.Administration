// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


namespace Microsoft.IIS.Administration.Certificates
{
    using AspNetCore.Mvc;
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using System.Linq;
    using Core.Http;
    using Core.Utils;
    using Core;

    public class CertificatesController : ApiBaseController
    {
        [HttpGet]
        [ResourceInfo(Name = Defines.CertificatesName)]
        public object Get()
        {            
            List<object> refs = new List<object>();
            Fields fields = Context.Request.GetFields();
            const StoreLocation sl = CertificateHelper.STORE_LOCATION;
            var certs = new Dictionary<string, IEnumerable<X509Certificate2>>();

            // Filter (intended_purpose)
            string intendedPurpose = Context.Request.Query["intended_purpose"];

            // Filter (store_name)
            string storeName = Context.Request.Query["store_name"];


            foreach (string sn in CertificateHelper.SUPPORTED_STORES) {

                if (string.IsNullOrEmpty(storeName) || sn.Equals(storeName, StringComparison.OrdinalIgnoreCase)) {
                    certs.Add(sn, CertificateHelper.GetCertificates(sn, sl));
                }
            }

            if (intendedPurpose != null) {
                foreach (var store in certs.Keys) {
                    certs[store] = certs[store].Where(cert => {
                        return CertificateHelper.GetEnhancedUsages(cert).Any(s => s.Equals(intendedPurpose, StringComparison.OrdinalIgnoreCase));
                    });
                }
            }

            // Build references in the scope of the store because references have dependence on store name and location
            foreach (KeyValuePair<string, IEnumerable<X509Certificate2>> store in certs) {
                foreach (var cert in store.Value) {
                    refs.Add(CertificateHelper.ToJsonModelRef(cert, store.Key, sl, fields));
                    cert.Dispose();
                }
            }

            // All certs disposed.
            certs = null;

            // Set HTTP header for total count
            this.Context.Response.SetItemsCount(refs.Count());

            return new {
                certificates = refs
            };
        }

        [HttpGet]
        [ResourceInfo(Name = Defines.CertificateName)]
        public object Get(string id)
        {
            CertificateId certId = new CertificateId(id);

            using (X509Certificate2 cert = CertificateHelper.GetCert(certId.Thumbprint, certId.StoreName, certId.StoreLocation)) {
                if (cert == null) {
                    return NotFound();
                }

                return CertificateHelper.ToJsonModel(cert, certId.StoreName, certId.StoreLocation, Context.Request.GetFields());
            }
        }
    }
}
