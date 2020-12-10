USE `3deposit`;

INSERT INTO roles (`role_name`)
VALUES ('admin'),
       ('manager'),
       ('uploader'),
       ('viewer');


INSERT INTO deposit_types (`type`)
VALUES ('model'),
       ('video'),
       ('vr');


INSERT INTO metadata_fields (`label`, `schema`, `tag`, `note`, `required`)
VALUES (
            'Title', 
            'dc', 
            'title', 
            'If there are more than one title given, please label one as "preferred" and others as "alternative". Example: Mona Lisa (preferred); Portrait of the Wife of Francesco del Giocondo (alternative)',
            1
       ),
       (
           'Creator',
           'dc',
           'creator',
           'Include the nationality and important date of the creator, if any. If the creator is unknown, please label it as "unknown". Example: Vincent van Gogh (Dutch, 1953-1890)',
           1
       ),
       (
           'Date',
           'dc',
           'date',
           'Please follow YYYY-MM-DD format if full date is available. Otherwise, month and year (YYYY-MM) or just year (YYYY) may be used. If the date is unknown, please label it as "unknown".',
           1
       ),
       (
           'Work Type',
           'cdwalite',
           'workType',
           'Recommended best practice is to use a controlled vocabulary such as the DCMI Type Vocabulary (http://dublincore.org/specifications/dublin-core/dcmi-type-vocabulary/) or AAT(https://www.getty.edu/research/tools/vocabularies/aat/). Example: "historical map"',
           1
       ),
       (
           'Identifier',
           'dc',
           'identifier',
           'Identifier is an unambiguous reference to the resource within a given context. Recommended best practice is to identify the resource by means of a string conforming to a formal identification system.',
           1
       ),
       (
           'Location/Repository',
           'cdwalite',
           'locationWrap',
           'The name and geographic location of the repository that is currently responsible for the work. Also may include creation location, discovery location, and other former locations. If the work is lost, destroyed, has location unknown, or the work is in an anonymous private collection, indicate this.',
           1
       ),
       (
           'Measurements',
           'cdwalite',
           'displayMeasurements',
           'Information about the dimensions, size, or scale of the work, presented in a syntax suitable for display to the end-user and including any necessary indications of uncertainty, ambiguity, and nuance. Example: "88.5 x 40 cm (34 7/8 x 15 3/4 inches)"',
           0
       ),
       (
           'Style',
           'cdwalite',
           'style',
           'Term that identifies the named, defined style, historical or artistic period, movement, group, or school whose characteristics are represented in the work being catalogued. Recommended best practice is to use a controlled vocabulary such as AAT (https://www.getty.edu/research/tools/vocabularies/aat/). Example: "Renaissance"',
           0
       ),
       (
           'Culture',
           'cdwalite',
           'culture',
           'Name of the culture, people, or nationality from which the work originated. Recommended best practice is to use a controlled vocabulary such as AAT (https://www.getty.edu/research/tools/vocabularies/aat/) or TGN (http://www.getty.edu/research/tools/vocabularies/tgn/). Example: "French"',
           0
       ),
       (
           'Descriptive Note',
           'cdwalite',
           'descriptiveNote',
           'A relatively brief essay-like text that describes the content and context of the work, including comments and an interpretation that may supplement, qualify, or explain the physical characteristics, subject, circumstances of creation or discovery, or other information about the work.',
           0
       ),
       (
           'Source Descriptive Note',
           'cdwalite',
           'sourceDescriptiveNote',
           'The source for the descriptive note, generally a published source. Example: "Hardin, Jennifer, The Lure of Egypt, St. Petersburg: Museum of Fine Arts, 1995."',
           0
       ),
       (
           'Related Work Set',
           'cdwalite',
           'relatedWorkWrap',
           'Please indicate the link to the related work, the relationship type, the label of the related work, the location of related work in this set. Example: "the object is part of Medical Artefact Collection in the Spurlock Museum (https://www.spurlock.illinois.edu/blog/p/medical-artifacts-at/355)"',
           0
       ),
       (
           'Rights',
           'dc',
           'right',
           'Please indicate information about rights held in and over the resource. Typically, rights information includes a statement about various property rights associated with the resource, including intellectual property rights.',
           1
       );