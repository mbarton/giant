

import React, {useEffect, useState} from "react";
import {GiantState} from "../../types/redux/GiantState";
import {GiantDispatch} from "../../types/redux/GiantDispatch";
import {connect} from "react-redux";
import '@elastic/eui/dist/eui_theme_light.css';
import {WorkspaceMetadata} from "../../types/Workspaces";
import {bindActionCreators} from "redux";
import {getCollections} from "../../actions/collections/getCollections";
import {Collection} from "../../types/Collection";
import {getDefaultCollection} from "../Uploads/UploadTarget";
import IngestionEvents from "./IngestionEvents";
import {PartialUser} from "../../types/User";
import {EuiProvider, EuiSelect} from "@elastic/eui";
import {getWorkspacesMetadata} from "../../actions/workspaces/getWorkspacesMetadata";
import {EuiFormControlLayout} from "@elastic/eui";
import {EuiFormLabel} from "@elastic/eui";


function MyUploads(
    props: {
        getCollections: (dispatch: any) => any,
        getWorkspacesMetadata: (dispatch: any) => any,
        collections: Collection[],
        currentUser?: PartialUser,
        workspacesMetadata: WorkspaceMetadata[],
          }) {
    const [defaultCollection, setDefaultCollection] = useState<Collection>()

    const [selectedWorkspace, setSelectedWorkspace] = useState<string>("all")

    useEffect(() => {
        props.getCollections({})
        props.getWorkspacesMetadata({})
    }, [props.getCollections, props.getWorkspacesMetadata])

    useEffect(() => {
        if (props.currentUser && props.collections.length > 0) {
            setDefaultCollection(getDefaultCollection(props.currentUser.username, props.collections))
        }
    }, [props.collections, props.currentUser])


    return (
        <div className='app__main-content'>
        <h1 className='page-title'>My workspace uploads</h1>
        <EuiProvider colorMode="light">
            {defaultCollection &&
                <>
                {props.workspacesMetadata.length > 0 &&
                    <EuiFormControlLayout prepend={<EuiFormLabel htmlFor={"workspace-picker"}>Workspace</EuiFormLabel>}>
                    <EuiSelect
                        value={selectedWorkspace}
                        onChange={(e) => setSelectedWorkspace(e.target.value)}
                        id={"workspace-picker"}
                        options={
                        [{value: "all", text: "All workspaces"}].concat(
                            props.workspacesMetadata.map((w: WorkspaceMetadata) =>
                                ({value: w.name, text: w.name}))
                        )
                    }>
                    </EuiSelect>
                    </EuiFormControlLayout>
                }
                 <IngestionEvents
                     collectionId={defaultCollection.uri}
                     workspaces={props.workspacesMetadata.filter((w) => selectedWorkspace === "all" || w.name === selectedWorkspace)}
                     breakdownByWorkspace={true}
                 ></IngestionEvents>
                </>
            }
        </EuiProvider>
                </div>

    )
}


function mapStateToProps(state: GiantState) {
    console.log(state)
    return {
        workspacesMetadata: state.workspaces.workspacesMetadata,
        currentUser: state.auth.token?.user,
        collections: state.collections
    };
}

function mapDispatchToProps(dispatch: GiantDispatch) {
    return {
        getCollections: bindActionCreators(getCollections, dispatch),
        getWorkspacesMetadata: bindActionCreators(getWorkspacesMetadata, dispatch),
    };
}

export default connect(mapStateToProps, mapDispatchToProps)(MyUploads);