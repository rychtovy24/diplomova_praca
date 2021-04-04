import xml.etree.ElementTree as ET
from rdflib.namespace import RDF, RDFS
from rdflib import URIRef, BNode, Literal, Namespace
from rdflib import Graph

CVE_OWL = URIRef("https://cve.mitre.org/about/terminology.html#CVE")
CVE_has_description = URIRef("http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#hasDescription")
CVE_has_reference = URIRef("http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#hasReference")
CVE_has_title = URIRef("http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#hasTitle")
REFERENCE_OWL = URIRef("http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#Reference")
REFERENCE_has_description = CVE_has_description
REFERENCE_has_ref_id = URIRef("http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#hasRefID")
REFERENCE_has_source = URIRef("http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#hasSource")

CVE_NAMESPACE = Namespace("https://cve.mitre.org/about/terminology.html#")


CVE_IRI = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="


class Reference:
    def __init__(self, id, ref_id, desc, source):
        self.iri = URIRef(id)
        self.ref_id = ref_id
        self.description = desc
        self.source = source

    def __repr__(self):
        rep = [
            "    Reference(",
            "      iri = " + self.iri,
            "      ref_id = " + self.ref_id,
            "      description = " + self.description,
            "      source = " + self.source,
            "    )"
        ]
        return '\n'.join(rep)


class CVE:
    def __init__(self, id, desc):
        self.id = id
        self.iri = URIRef(CVE_IRI + id)
        self.description = desc
        self.references = []

    def __repr__(self):
        rep = [
            "CVE(", 
            "  iri = " + self.iri,
            "  description = " + self.description,
            "  references = [\n" + ',\n'.join([ref.__repr__() for ref in self.references]),
            ")"
        ]
        return '\n'.join(rep)

    def add_reference(self, ref):
        self.references.append(ref)

    def write_CVE(self, graph):
        graph.add( (self.iri, RDF.type, CVE_OWL) )
        graph.add( (self.iri, RDFS.label, Literal(self.id)) )
        graph.add( (self.iri, CVE_has_description, Literal(self.description)) )
        graph.add( (self.iri, CVE_has_title, Literal(self.id)) )
        for reference in self.references:
            graph.add( (reference.iri, RDF.type, REFERENCE_OWL) )
            graph.add( (reference.iri, REFERENCE_has_description, Literal(reference.description)) )
            graph.add( (reference.iri, REFERENCE_has_source, Literal(reference.source)) )
            graph.add( (self.iri, CVE_has_reference, reference.iri) )

    


tree = ET.parse('cve_allitems.xml')
root = tree.getroot()
cve_dic = {}
ref_dic = {}
count = 0
for child in root:
    if child.tag != 'item':
        continue
    cve_id = child.attrib['name']
    cve = CVE(cve_id, "")
    cve_dic[cve_id] = cve
    desc = ""
    for item_child in child:
        if item_child.tag == 'desc':
            cve.description = item_child.text
        elif item_child.tag == 'refs':
            for ref in item_child:
                if 'url' in ref.attrib.keys():
                    refer = Reference(ref.attrib['url'], "", ref.text, ref.attrib['source'])
                    ref_dic[refer.iri] = refer
                    cve.add_reference(refer)
    count += 1
    #if count > 1000:
    #    break

graphs = {}
for i in range(1999, 2022):
    graphs[str(i)] = Graph()
    graphs[str(i)].bind('cve', CVE_NAMESPACE)

for key in cve_dic:
    year = key.split('-')[1]
    cve_dic[key].write_CVE(graphs[year])
for i in range(1999, 2022):
    year = str(i)
    with open('cve_generate_data_'+year+'.xml', 'w', encoding="utf-8") as f:
        print(graphs[year].serialize(format="xml").decode("utf-8"), file=f)
    del graphs[year]
    

