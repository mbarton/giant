

import {useEffect, useState} from "react";
import {GiantState} from "../../types/redux/GiantState";
import {GiantDispatch} from "../../types/redux/GiantDispatch";
import {connect} from "react-redux";
import '@elastic/eui/dist/eui_theme_light.css';
import {WorkspaceMetadata} from "../../types/Workspaces";
import {bindActionCreators} from "redux";
import {getCollections} from "../../actions/collections/getCollections";
import {Collection} from "../../types/Collection";
import {getDefaultCollection} from "../Uploads/UploadTarget";
import {IngestionEvents} from "./IngestionEvents";
import {PartialUser} from "../../types/User";
import {EuiButtonGroup, EuiFlexGroup, EuiProvider, EuiSelect} from "@elastic/eui";
import {getWorkspacesMetadata} from "../../actions/workspaces/getWorkspacesMetadata";
import {EuiFormControlLayout} from "@elastic/eui";
import {EuiFormLabel} from "@elastic/eui";
import { css } from "@emotion/react";




function MyUploads(
    {getCollections, getWorkspacesMetadata, collections, currentUser, workspacesMetadata}: {
        getCollections: (dispatch: any) => any,
        getWorkspacesMetadata: (dispatch: any) => any,
        collections: Collection[],
        currentUser?: PartialUser,
        workspacesMetadata: WorkspaceMetadata[],
          }) {
    const [defaultCollection, setDefaultCollection] = useState<Collection>()

    const [selectedWorkspace, setSelectedWorkspace] = useState<string>("all");

    const [toggleIdSelected, setToggleIdSelected] = useState(`all__0`);      

    useEffect(() => {
        getCollections({})
        getWorkspacesMetadata({})
    }, [getCollections, getWorkspacesMetadata])

    useEffect(() => {
        if (currentUser && collections.length > 0) {
            setDefaultCollection(getDefaultCollection(currentUser.username, collections))
        }
    }, [collections, currentUser])

    const toggleFilterButtons = [
        { id: `all__0`, label: 'all' },
        { id: `errors__1`, label: 'errors only' },
      ];

    return (
        <div className='app__main-content'>
        <h1 className='page-title'>My workspace uploads</h1>
        <EuiProvider globalStyles={false} colorMode="light">
            {defaultCollection &&
                <>
                {workspacesMetadata.length > 0 &&
                <EuiFlexGroup>
                    <EuiFormControlLayout prepend={<EuiFormLabel htmlFor={"workspace-picker"}>Workspace</EuiFormLabel>}>
                        <EuiSelect
                            value={selectedWorkspace}
                            onChange={(e) => setSelectedWorkspace(e.target.value)}
                            id={"workspace-picker"}
                            options={
                                [{value: "all", text: "All workspaces"}].concat(
                                    workspacesMetadata.map((w: WorkspaceMetadata) =>
                                        ({value: w.name, text: w.name}))
                                )
                            }>
                        </EuiSelect>                     
                    </EuiFormControlLayout>
                    <EuiButtonGroup 
                        css={css`border: none;`}
                        legend="selection group to show all events or just the errors"
                        options={toggleFilterButtons} 
                        idSelected={toggleIdSelected}
                        onChange={(id) => setToggleIdSelected(id)}
                    >                                
                    </EuiButtonGroup> 
                </EuiFlexGroup>
                }
                 <IngestionEvents
                     collectionId={defaultCollection.uri}
                     workspaces={workspacesMetadata.filter((w) => selectedWorkspace === "all" || w.name === selectedWorkspace)}
                     breakdownByWorkspace={true}
                     showErrorsOnly={toggleIdSelected === 'errors__1'}
                 ></IngestionEvents>
                </>
            }
        </EuiProvider>
                </div>

    )
}


function mapStateToProps(state: GiantState) {
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